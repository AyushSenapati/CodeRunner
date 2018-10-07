import os

from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, get_object_or_404, HttpResponse, redirect
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User

from .models import QuestionAnswer
from .forms import SignUpForm
from .tokens import account_activation_token

import subprocess as sp
# import tempfile
from datetime import datetime
from pylint import epylint as lint


APP_NAME = "CODERUNNER"
LOGO = ' '.join(list(APP_NAME))
APP = {'name': APP_NAME, 'logo': LOGO, 'title': None}
FILE_DIR = "/tmp/coderunner_"
FILE_EXT = ".py"


# Create your views here.
def signup(request):
    """Extend the basic UserCreationForm to accept email
    by using the custom SignUpForm
    and confirm the email address using an activation link
    """

    # Set the title of the webpage
    APP['title'] = 'Sign up'

    if request.user.is_authenticated:
        return redirect('/home')

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            email_subject = 'Activate your CodeRunner account'
            email_message = render_to_string(
                'registration/account_activation_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    # Decode the base64 encoded data before sending,
                    # else the byte code will be wrapped with str obj
                    # which can't be decoded further
                    'uid': urlsafe_base64_encode(
                        force_bytes(user.pk)).decode(),
                    'token': account_activation_token.make_token(user)
                })
            user.email_user(email_subject, email_message)
            return redirect('/accounts/signup/account_activation_sent')
    else:
        form = SignUpForm()
    return render(request,
                  'registration/signup.html',
                  {'form': form, 'app': APP})


def invalid(request):
    """This view has been created just to test
    how account activation invalid view is rendered"""
    reasons = []
    return render(request, 'registration/account_activation_invalid.html',
                  {'app': APP, 'reasons': reasons})


def activate(request, uidb64, token):
    """View to handle the activation
    process of a new user account"""

    # Try to decode the UID from the activation
    # URL and check if UID exists in the database

    APP['title'] = 'Account activation'
    try:
        uid = urlsafe_base64_decode(uidb64.encode())
        user = User.objects.get(pk=uid)
        if user.is_active:
            reasons = ['Account is already active', ]
            return render(request,
                          'registration/account_activation_invalid.html',
                          {'reasons': reasons, 'app': APP})
    except User.DoesNotExist:
        reasons = ['Account not found', ]
        return render(request,
                      'registration/account_activation_invalid.html',
                      {'reasons': reasons, 'app': APP})
    except (TypeError, ValueError, OverflowError) as e:
        raise e

    # If user is found at the UID, check the
    # token. Upon successful token validation
    # activate the user account, authenticate
    # the user and redirect to the home page
    if user is not None:
        if account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            auth_login(request, user)
            return redirect('/home')
        else:
            reasons = ['Token validation failed', ]
            return render(request,
                          'registration/account_activation_invalid.html',
                          {'reasons': reasons, 'app': APP})
    else:
        reasons = ['Account not found', ]
        return render(request,
                      'registration/account_activation_invalid.html',
                      {'reasons': reasons, 'app': APP})


def account_activation_sent(request):
    """After successfully sending the
    account activation link, render this web page
    """
    return render(request,
                  'registration/account_activation_sent.html',
                  {'app': APP})


def home(request):
    """Return welcome message with listing
    all available questions to appear
    """

    APP['title'] = 'H O M E'
    user = request.user
    questions = QuestionAnswer.objects.order_by('-id')[:5]
    return render(request, 'coderunner/index.html',
                  {'questions': questions,
                   'user': user,
                   'app': APP})


@csrf_exempt
def validate_program(request):
    """
    Handles AJAX calls for realtime code linting event
    """

    # Track the frequency of the event
    # occurance and display it on STDOUT
    request.session['event_count'] += 1
    print(f"\n(VALIDATE_PROGRAM view) Event occurance: "
          f"{request.session['event_count']} times")

    # Get the code snippet from the POST data
    snippet = request.POST.get('snippet', '')

    # SLOW DOWN THE LINTING PROCESS to save system resources:
    # If Linting_event_occurance_interval < 2 sec,
    # then don't process the snippet for linting
    # and update "last_event_time"
    # (Reduced the interval to 2 from 5 for realtime linting)
    if (datetime.timestamp(datetime.now()) -
            request.session['last_event_time']) < 1:

        request.session['last_event_time'] = datetime.timestamp(datetime.now())
        return JsonResponse(None, safe=False)

    # By this time, a temp file
    # "django_ayush_[random_string].py" for the user
    # must have been created while accessing "details/" view
    # use that temp file for code linting.
    # If temp file not found -> log the exception
    # and create a temp file
    print(f"\n(VALIDATE_PROGRAM view) SNIPPET:"
          f"\n{snippet}\n-------------------------")

    # try:
    #     f = open(request.session['file_name'], 'w')
    #     for t in snippet:
    #         f.write(t)
    #     f.flush()
    # except Exception as e:
    #     with tempfile.NamedTemporaryFile(prefix='django_ayush_', dir='/tmp',
    #                                      suffix='.py', delete=False) as temp:
    #         request.session['file_name'] = temp.name
    #         for t in snippet:
    #             temp.write(t.encode('utf-8'))
    #         temp.flush()

    with open(request.session['file_name'], 'w') as fo:
        for ch in snippet:
            fo.write(ch)
            fo.flush()

    # Process the code snippet stored in the temp file to get linting errors
    (pylint_stdout, pylint_stderr) = lint.py_run(request.session['file_name'],
                                                 return_std=True)
    errors = pylint_stdout.getvalue()
    error_list = errors.splitlines(True)
    error_list = [error for error in error_list if
                  request.session['file_name'] in error]

    # Initialize a <dict type> container
    # to hold all the linting information
    data = {}

    # Use a <int type> key in the data dict to
    # store more than one linting issues
    key = 0

    # Loop over the error list to populate <dict type> container
    for error in error_list:
        key += 1
        line_num = error.split(':')[1]
        error_message = error.split(':')[2].strip()
        print(f"Linting Errors: {error_message}")
        # err_code, err_code_desc, *args = \
        #     re.findall(r'\((.*?)\)', tmp)[0].split(',')
        data[key] = {'line_num': line_num, 'error_message': error_message}

    # If the event occurance interval
    # was more than 2 sec, update the last_event_time
    request.session['last_event_time'] = datetime.timestamp(datetime.now())

    # If <dict type> container has been
    # populated return the dict, else return None
    print(f"Dict data: {data}")
    if data == {}:
        data = None

    # Remove the file after linting is done
    # if os.path.exists(request.session['file_name']):
        # os.remove(request.session['file_name'])

    return JsonResponse(data, safe=False)


def details(request, qid):
    """Display the question and its description.
    Provide a form with textArea to write program.
    """
    print("\n(DETAILS view) SESSION DATA:\n-------------------------")
    for key, value in request.session.items():
        print(f"{key} => {value}")
    print('---------------------------\n')

    # Set title of the webpage
    APP['title'] = 'D E T A I L S'

    # Initialize a temp file if not already created
    # for the user to handle user code snippets

    request.session['file_name'] = FILE_DIR +\
        request.session['_auth_user_hash'] +\
        FILE_EXT

    # Initialize an event_counter to numeric Zero
    # to track the linting_event_occurance.
    # Increase the counter upon event occurance in
    # linting event handler view
    request.session['event_count'] = 0

    # Initialize last_event_time to current timestamp
    # to track the frequency of linting_event_occurance
    # update this time in linting event handler view
    request.session['last_event_time'] = datetime.timestamp(datetime.now())

    question = get_object_or_404(QuestionAnswer, pk=qid)

    # Calculate the pass percentage of the question_id
    if question.times_appeared != 0:
        pass_percent = int((question.times_correct /
                            question.times_appeared) * 100)
    else:
        pass_percent = 0
    return render(request, 'coderunner/details.html',
                  {'question': question,
                   'pass_percent': pass_percent,
                   'app': APP})


def program(request, qid):
    print(f"Received POST request {str(request.POST)}")
    button = request.POST.get('button')
    print(f"Inside program view and button pressed is: [[{button}]]")
    PROGRAM_RUN_FLAG = False

    # If Run button is pressed
    if button == 'Run':
        output = run_code(request, qid)
        print(f"Output: {output}")
        PROGRAM_RUN_FLAG = True
        # return HttpResponse(output)

    if PROGRAM_RUN_FLAG:
        return JsonResponse(output, safe=False)
    else:
        return HttpResponse('Are you sure? You have not run the code yet.')


@csrf_exempt
def run_code(request, qid):
    """Get the submitted code,
    run it and return the output to the user
    """

    qid_obj = QuestionAnswer.objects.get(pk=qid)
    qid_obj.times_appeared += 1

    # Store the submitted program in session variable
    # request.session['program'] = request.POST['program']

    snippet = request.POST['snippet']

    # Create a temporary Python file to store submitted program
    with open(request.session['file_name'], 'w') as fo:
        for ch in snippet:
            fo.write(ch)

    timeout = None
    stime = datetime.timestamp(datetime.now())
    cmd = 'python ' + request.session["file_name"]
    p = sp.Popen(cmd, shell=True, stdin=sp.PIPE, stdout=sp.PIPE,
                 stderr=sp.STDOUT, close_fds=True)
    try:
        (output, error) = p.communicate(timeout=timeout)
        exec_time = datetime.timestamp(datetime.now()) - stime

        # Strip trailing spaces and new lines
        output = output.decode('utf-8').strip()
    except sp.TimeoutExpired:
        output = "Timeout expired"

        # If Timeout expires set exec time to None
        exec_time = None
    except Exception as e:
        raise e

    print(f"Expected output: {qid_obj.expected_output}"
          f"\tType: {type(qid_obj.expected_output)}\n"
          f"Captured output: {output}\tType: {type(output)}")
    if str(output) == str(qid_obj.expected_output):
        qid_obj.times_correct += 1
        print('Got expected output!!')
    else:
        qid_obj.times_wrong += 1

    # After completing execution delete the created Python file
    # if os.path.exists(request.session['file_name']):
    #     os.remove(request.session['file_name'])

    # Save all database updates
    qid_obj.save()

    data = {
        'timeout': timeout,
        'exec_time': exec_time,
        'output': output.split('\n')
    }

    return JsonResponse(data, safe=False)


def result(request, qid):
    """Show results"""

    return render(request, 'coderunner/result.html', {'result': result})

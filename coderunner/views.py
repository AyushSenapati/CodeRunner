import os

from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, get_object_or_404, HttpResponse, redirect
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User, Permission
from django.contrib.auth.decorators import user_passes_test
from django.views.generic.edit import UpdateView, DeleteView

from .models import Questions, Submissions
from .forms import SignUpForm, PublishQuestionForm
from .tokens import account_activation_token

import subprocess as sp
from datetime import datetime
from pylint import epylint as lint

import logging

logger = logging.getLogger(__name__)
APP_NAME = "CODERUNNER"
LOGO = ' '.join(list(APP_NAME))
APP = {'name': APP_NAME, 'logo': LOGO, 'title': None}
FILE_DIR = "/tmp/coderunner_"
FILE_EXT = ".py"
REQ_SCORE_TO_PUBLISH = 20

try:
    CAN_PUBLISH_QUESTION = {
        'perm_obj': Permission.objects.get(name='Can add Questions'),
        'string': 'coderunner.add_questions'
    }
except Exception as e:
    logger.error(e)


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
            if user.is_active:
                logger.warning(f'{user.username} is set '
                               'to active before checking activation token')
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
            logger.info('Account activation link '
                        f'has been sent to {request.user}')
            user.email_user(email_subject, email_message)
            return redirect('/accounts/signup/account_activation_sent')
    else:
        form = SignUpForm()
    return render(request,
                  'registration/signup.html',
                  {'form': form, 'app': APP})


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
            logger.warning(f'Account: {user.username} is already active!')
            reasons = ['Account is already active', ]
            return render(request,
                          'registration/account_activation_invalid.html',
                          {'reasons': reasons, 'app': APP})
    except User.DoesNotExist:
        logger.warning(f'Account: {user.username} has not been created yet!')
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
            logger.warning('Token tampering '
                           f'detected for Account: {user.username}')
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


def index(request):
    logger.debug(f'{request.user} is accessing index page')
    return redirect('/home/')


def home(request):
    """Return welcome message with listing
    all available questions to appear
    """

    APP['title'] = 'H O M E'
    user = request.user
    if user.has_perm(CAN_PUBLISH_QUESTION['string']):
        publish_perm = True
    else:
        publish_perm = False

    # Returns empty QuerySet if username
    # does not exist or match with any of the submissions
    submissions = Submissions.objects.filter(
        username__username=user)

    questions = Questions.objects.order_by('-id')[:5]

    return render(request, 'coderunner/index.html',
                  {'questions': questions,
                   'submissions': submissions,
                   'user': user,
                   'publish_perm': publish_perm,
                   'app': APP})


@user_passes_test(lambda u: u.has_perm(CAN_PUBLISH_QUESTION['string']),
                  login_url='/home/')
def publish_question(request):
    """View to publish a question
    Before accessing the view do check
    if the user has minimum score """

    form = PublishQuestionForm(request.POST or None)
    if form.is_valid():
        publish = form.save(commit=False)

        # Save the authenticated user
        # as the author of the question
        publish.author = request.user

        publish.save()
        return redirect('/home/')
    return render(request,
                  'coderunner/publish_question.html',
                  {'form': form, 'app': APP})


def check_authorization(request, qid_obj):
    """ Check if the user is
    authorized to modify the question,
    by verifying if the requesting user
    is the author of the question

    :param qid_obj:     Questions object
    :return True:       If user is authorized
    :return False:      User is unauthorized

    """
    logger.debug(f'Checking authorization for user {request.user}')
    if request.user == qid_obj.author:
        return True
    else:
        return False


class ModifyQuestion(UpdateView):
    """ View to allow the author of
    the question to modify the question
    """

    model = Questions
    template_name = 'coderunner/modify_question.html'
    form_class = PublishQuestionForm
    success_url = '/home/'

    def dispatch(self, request, *args, **kwargs):
        """Override the dispatch method
        to check if the requesting user
        is authorized to modify the question
        """

        qid_obj = get_object_or_404(Questions, pk=kwargs.get('pk', None))
        if not check_authorization(request, qid_obj):
            logger.debug(f'{request.user} is not '
                         f'authorized to modify {qid_obj.question_text}')
            return redirect('/home/')
        else:
            logger.debug(f'{request.user} is authorized '
                         f'to modify {qid_obj.question_text}')
            return super().dispatch(request, *args, **kwargs)


class DeleteQuestion(DeleteView):
    """Generic class based view to implement
    delete fucntionalities for the created objects
    Before rendering the view do check if the user
    is authorized to delete the object
    """

    model = Questions
    success_url = '/home/'

    def dispatch(self, request, *args, **kwargs):
        qid_obj = get_object_or_404(Questions, pk=kwargs.get('pk', None))
        if not check_authorization(request, qid_obj):
            logger.debug(f'{request.user} is not '
                         f'authorized to delete {qid_obj.question_text}')
            return redirect('/home/')
        else:
            logger.debug(f'{request.user} is authorized '
                         f'to delete {qid_obj.question_text}')
            return super().dispatch(request, *args, **kwargs)


@csrf_exempt
def validate_program(request):
    """
    Handles AJAX calls for realtime code linting event
    """

    # Track the frequency of the event
    # occurance and display it on STDOUT
    request.session['event_count'] += 1
    logger.debug(f"Event occurance: {request.session['event_count']} times")

    # Get the code snippet from the POST data
    snippet = request.POST.get('snippet', '')

    # SLOW DOWN THE LINTING PROCESS to save system resources:
    # If Linting_event_occurance_interval < 1 sec,
    # then don't process the snippet for linting
    # and update "last_event_time"
    # (Reduced the interval to 1 from 5 for realtime linting)
    if (datetime.timestamp(datetime.now()) -
            request.session['last_event_time']) < 1:

        request.session['last_event_time'] = datetime.timestamp(datetime.now())
        return JsonResponse(None, safe=False)

    # By this time, a temp file
    # "coderunner_[random_string].py" for the user
    # must have been created while accessing "details/" view
    # use that temp file for code linting.

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
        logger.debug(f"Linting Errors: {error_message}")
        data[key] = {'line_num': line_num, 'error_message': error_message}

    # If the event occurance interval
    # was more than 2 sec, update the last_event_time
    request.session['last_event_time'] = datetime.timestamp(datetime.now())

    # If <dict type> container has been
    # populated return the dict, else return None
    logger.debug(f"Dict data: {data}")
    if data == {}:
        data = None

    return JsonResponse(data, safe=False)


def details(request, qid):
    """Display the question and its description.
    Provide a form with textArea to write program.
    """
    logger.debug("\n(DETAILS view) SESSION DATA:\n-------------------------")
    for key, value in request.session.items():
        logger.debug(f"{key} => {value}")
    logger.debug('---------------------------\n')

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

    question = get_object_or_404(Questions, pk=qid)

    # Calculate the pass percentage of the question_id
    if question.times_submitted != 0:
        pass_percent = int((question.times_correct /
                            question.times_submitted) * 100)
    else:
        pass_percent = 0

    return render(request, 'coderunner/details.html',
                  {'question': question,
                   'pass_percent': pass_percent,
                   'app': APP})


def program(request, qid):
    """
    View to handle code submit action
    """

    # Append testcase status [passed/failed]
    testcase_status = []

    qid_obj = Questions.objects.get(pk=qid)
    usr_obj = User.objects.get(username=request.user)

    # If the user has already submitted a solution for
    # the question get the submit_obj to update the submission
    # else create a new object to add the submission
    try:
        submit_obj = Submissions.objects.get(username=usr_obj,
                                             question=qid_obj)
        already_submitted_flag = True
    except Submissions.DoesNotExist as e:
        submit_obj = Submissions(username=usr_obj, question=qid_obj)
        already_submitted_flag = False

    snippet = request.POST['program']

    # Create a temporary Python file to store submitted program
    with open(request.session['file_name'], 'w') as fo:
        for ch in snippet:
            fo.write(ch)

    # Get the timeout set for the question
    timeout = qid_obj.timeout
    if timeout == 0:
        timeout = None

    testcase = {'input': qid_obj.submit_testcase1_input.split('\n'),
                'output': qid_obj.submit_testcase1_output
                }

    data = execute_testcase(request, timeout, testcase)
    testcase_status.append(data['output'])

    testcase = {'input': qid_obj.submit_testcase2_input.split('\n'),
                'output': qid_obj.submit_testcase2_output
                }

    data = execute_testcase(request, timeout, testcase)
    testcase_status.append(data['output'])

    score = qid_obj.score
    userprofile_score = usr_obj.userprofile.score

    # Increase the times_submitted counter
    qid_obj.times_submitted += 1

    if 'failed' in testcase_status:
        url = request.path.replace('program', 'details')

        qid_obj.times_wrong += 1
        data['output'] = 'Testcase: failed, Check your code and try again'

        if not already_submitted_flag:
            # Upon incorrect submission reduce the profile score
            # by half the score set in the question. In case of insufficient
            # profile score, set profile score to numberic Zero
            if userprofile_score >= score // 2:
                userprofile_score -= score // 2
            else:
                userprofile_score = 0

            # Update userprofile score in DB
            usr_obj.userprofile.score = userprofile_score

            # If user does not satisfy required
            # critaria remove PUBLISH Question permission
            if userprofile_score < REQ_SCORE_TO_PUBLISH:
                usr_obj.user_permissions.remove(
                    CAN_PUBLISH_QUESTION['perm_obj']
                )

            msg = "Failed to pass the testcases. " +\
                f"You have lost { score // 2 } points."

        else:
            msg = "Failed to pass the testcases this time. " +\
                "But you already have submitted correct solution"

        # Save all changes to DB
        qid_obj.save()
        usr_obj.save()
        return render(request,
                      'coderunner/result.html',
                      {'app': APP,
                       'testcases': testcase_status,
                       'msg': msg,
                       'try_again_url': url})
    else:
        qid_obj.times_correct += 1

        if not already_submitted_flag:
            # If a user has not already submitted a solution for the
            # question, award the user with the score mentioned
            # by the author of the question upon successful submission
            userprofile_score += score

            # Update userprofile score in DB
            usr_obj.userprofile.score = userprofile_score

            # Upon correct code submission, store the snippet in DB
            submit_obj.submitted_snippet = snippet

            msg = "Successfully submitted. " +\
                f"You are awarded with {score} points"

            # Allow the user to publish a question if
            # (s)he satisfies required critaria
            if userprofile_score >= REQ_SCORE_TO_PUBLISH:
                usr_obj.user_permissions.add(CAN_PUBLISH_QUESTION['perm_obj'])
                msg = "Successfully submitted. " +\
                    f"You are awarded with {score} points." +\
                    "You can now publish a challenge"

        else:
            # If user has already submitted a correct solution,
            # only update the code snippet, don't allow the user
            # to earn points by submitting solutions to the
            # same questions repeatedly
            submit_obj.submitted_snippet = snippet
            msg = "Successfully re-submitted the solution."

        # Save all changes to DB
        qid_obj.save()
        usr_obj.save()
        submit_obj.save()

        return render(request,
                      'coderunner/result.html',
                      {'app': APP,
                       'testcases': testcase_status,
                       'msg': msg})


def execute_testcase(request, timeout, testcase):
    # store the current time stamp, execute the
    # user code and calculate the execution time
    # If exec time exceeds fail the solution
    stime = datetime.timestamp(datetime.now())

    # Initialize a list to contain all the command line argument
    cmd = ['python', request.session["file_name"]]
    for arg in testcase['input']:
        cmd.append(arg)

    logger.debug(f"Command going to execute: {cmd}")
    # Initialize a subprocess to execute user code
    p = sp.Popen(cmd, shell=False, stdin=sp.PIPE, stdout=sp.PIPE,
                 stderr=sp.STDOUT, close_fds=True)

    try:
        (output, error) = p.communicate(timeout=timeout)
        exec_time = datetime.timestamp(datetime.now()) - stime

        # Strip trailing spaces and new lines
        output = output.decode('utf-8').strip()

    except sp.TimeoutExpired:
        # If Timeout expires set exec time to None
        exec_time = None

        output = "Timeout expired"

    except Exception as e:
        raise e

    logger.debug(f"Expected output: [{testcase['output']}]"
                 f"\tType: {type(testcase['output'])}\n"
                 f"Captured output: [{output}]\tType: {type(output)}")

    if str(output) == str(str(testcase['output']).strip('\n')):
        output = 'passed'
    else:
        output = 'failed'

    data = {
        'timeout': timeout,
        'exec_time': exec_time,
        'output': output
    }

    return data


@csrf_exempt
def run_code(request, qid):
    """Get the submitted code,
    run it and return the output to the user
    """

    qid_obj = Questions.objects.get(pk=qid)
    # qid_obj.times_submitted += 1

    testcase = {'input': qid_obj.run_testcase1_input.split('\n'),
                'output': qid_obj.run_testcase1_output
                }

    snippet = request.POST['snippet']

    # Create a temporary Python file to store submitted program
    with open(request.session['file_name'], 'w') as fo:
        for ch in snippet:
            fo.write(ch)

    # Get the timeout set for the question
    timeout = qid_obj.timeout
    if timeout == 0:
        timeout = None

    data = execute_testcase(request, timeout, testcase)

    data['output'] = ['Testcase status: ' + data['output'], ]

    return JsonResponse(data, safe=False)

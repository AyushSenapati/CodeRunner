import os

from django.shortcuts import render, get_object_or_404, HttpResponse, redirect
# from django.utils.six import BytesIO
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required

from .models import QuestionAnswer

from subprocess import Popen, PIPE, STDOUT
import tempfile
from datetime import datetime
from pylint import epylint as lint


APP_NAME = "CodeRunner"
LOGO = ' '.join(list(APP_NAME))


def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_paswd = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_paswd)
            login(request, user)
            # return HttpResponseRedirect(reverse('home'))
            return redirect('/home/')
    else:
        form = UserCreationForm()
    return render(request,
                  'registration/signup.html', {'form': form})


# Create your views here.
def home(request):
    '''Return welcome message with listing
    all available questions to appear'''

    questions = QuestionAnswer.objects.order_by('-id')[:5]
    return render(request, 'coderunner/index.html',
                  {'questions': questions,
                   'app_name': APP_NAME, 'logo': LOGO})


@csrf_exempt
def validate_program(request):
    request.session['event_count'] += 1
    snippet = request.POST.get('snippet', '')
    print(f"##### Event occurance: {request.session['event_count']} times")

    # Slow down linting process
    # (Reduced the interval to 2 for realtime linting)
    if (datetime.timestamp(datetime.now()) -
            request.session['last_event_time']) < 2:

        request.session['last_event_time'] = datetime.timestamp(datetime.now())
        return JsonResponse(None, safe=False)

    # If a file does not exist for current session
    # then create one and store the submitted code
    try:
        f = open(request.session['file_name'], 'w')
        for t in snippet:
            f.write(t)
        f.flush()
    except Exception as e:
        with tempfile.NamedTemporaryFile(prefix='django_ayush_', dir='/tmp',
                                         suffix='.py', delete=False) as temp:
            request.session['file_name'] = temp.name
            for t in snippet:
                temp.write(t.encode('utf-8'))
            temp.flush()

    (pylint_stdout, pylint_stderr) = lint.py_run(request.session['file_name'],
                                                 return_std=True)
    errors = pylint_stdout.getvalue()
    error_list = errors.splitlines(True)
    error_list = [error for error in error_list if
                  request.session['file_name'] in error]

    data = {}
    key = 0
    for error in error_list:
        key += 1
        line_num = error.split(':')[1]
        error_message = error.split(':')[2].strip()
        print(error_message)
        # err_code, err_code_desc, *args = \
        #     re.findall(r'\((.*?)\)', tmp)[0].split(',')
        data[key] = {'line_num': line_num, 'error_message': error_message}

    print(data)
    if data == {}:
        data = None

    request.session['last_event_time'] = datetime.timestamp(datetime.now())
    return JsonResponse(data, safe=False)


@login_required
def details(request, qid):
    '''Display the question and its description.
    Provide a form to write program with submit action.'''

    # Set event counter for validate program to zero
    request.session['event_count'] = 0

    # Set event occurance interval to restrict continous linting
    request.session['last_event_time'] = datetime.timestamp(datetime.now())

    question = get_object_or_404(QuestionAnswer, pk=qid)
    if question.times_appeared != 0:
        pass_percent = int((question.times_correct /
                            question.times_appeared) * 100)
    else:
        pass_percent = 0
    return render(request, 'coderunner/details.html',
                  {'question': question, 'pass_percent': pass_percent,
                   'app_name': APP_NAME, 'logo': LOGO})


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
    '''Get the submitted code,
    run it and return the output to the user'''
    qid_obj = QuestionAnswer.objects.get(pk=qid)
    qid_obj.times_appeared += 1

    # Store the submitted program in session variable
    # request.session['program'] = request.POST['program']
    request.session['program'] = request.POST['snippet']

    # Create a temporary Python file to store submitted program
    with tempfile.NamedTemporaryFile(prefix='django_ayush_', dir='/tmp',
                                     suffix='.py', delete=False) as temp:
        request.session['file_name'] = temp.name
        for t in request.session['program']:
            temp.write(t.encode('utf-8'))
        temp.flush()

    cmd = 'python ' + request.session["file_name"]
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE,
              stderr=STDOUT, close_fds=True)
    output = p.stdout.read()

    # Strip trailing spaces and new lines
    output = output.decode('utf-8').strip()

    print(f"Expected output: {qid_obj.expected_output}"
          f"\tType: {type(qid_obj.expected_output)}\n"
          f"Captured output: {output}\tType: {type(output)}")
    if str(output) == str(qid_obj.expected_output):
        qid_obj.times_correct += 1
        print('Got expected output!!')
    else:
        qid_obj.times_wrong += 1

    # After completing execution delete the created Python file
    os.remove(request.session['file_name'])
    # TODO: Check if all session keys need to be deleted [Not Sure]

    # Save all database updates
    qid_obj.save()

    data = {'output': output.split('\n')}
    return JsonResponse(data, safe=False)


def result(request, qid):
    '''Show results'''

    return render(request, 'coderunner/result.html', {'result': result})

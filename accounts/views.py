from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, FileResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.cache import cache
from django.core.mail import send_mail
from django.views.decorators.cache import never_cache
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.template.loader import render_to_string
from datetime import timedelta
from .models import CustomUser, Document, SharedDocument
from .ipfs_module.ipfs_handler import IPFSHandler
from .eth_module.contract_handler import ContractHandler
from .db_module.db_handler import DBHandler
from .utils import generate_otp, send_otp_email, send_verification_email, send_password_reset_email
import os
import re
import logging
from pathlib import Path
import uuid


# Initialize logger and handlers
logger = logging.getLogger(__name__)
ipfs_handler = IPFSHandler()
db_handler = DBHandler("localhost", "root", "J@iswal9971", "web3")
contract_handler = ContractHandler()

# Constants
BASE_DIR = Path(__file__).resolve().parent
TEMP_PRIVATE_KEY = '6ae4a305B3768c467BeC609C3aF4488eB582639a'
CONTRACT_ADDRESS = "0x6ae4a305B3768c467BeC609C3aF4488eB582639a"

# Smart contract ABI
ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "fileName", "type": "string"},
            {"internalType": "string", "name": "fileHash", "type": "string"}
        ],
        "name": "storeFile",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "fileName", "type": "string"}],
        "name": "getFileHash",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "", "type": "string"}],
        "name": "fileHashes",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# Decorators
def no_cache_view(view_func):
    """Prevent view from being cached."""
    return never_cache(view_func)

# Views
def home(request):
    """Render the home page."""
    return render(request, 'base.html')

@no_cache_view
def login_view(request):
    """Handle user login with 2FA."""
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Validate input
        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return redirect('login')

        # Rate limiting
        ip = request.META.get('REMOTE_ADDR')
        attempts_key = f'login_attempts_{ip}'
        attempts = cache.get(attempts_key, 0)
        if attempts >= 5:
            messages.error(request, 'Too many login attempts. Please try again in 5 minutes.')
            return redirect('login')

        # Authenticate user
        try:
            user = authenticate(request, username=username, password=password)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            messages.error(request, 'An error occurred during authentication.')
            return redirect('login')

        if user is None:
            cache.set(attempts_key, attempts + 1, timeout=300)
            messages.error(request, 'Invalid username or password.')
            return redirect('login')

        if not user.is_email_verified:
            messages.error(request, 'Please verify your email before logging in.')
            return redirect('login')

        # Generate and send OTP for 2FA
        otp = generate_otp()
        cache.set(f'otp_{user.id}', otp, timeout=600)
        send_otp_email(user.email, otp)
        request.session['pending_user'] = user.id
        return redirect('otp_login')

    return render(request, 'login.html')

@no_cache_view
def otp_login(request):
    """Handle OTP verification for login."""
    if request.method == 'POST':
        otp = request.POST.get('otp')
        user_id = request.session.get('pending_user')

        if not user_id:
            messages.error(request, 'Session expired. Please log in again.')
            return redirect('login')

        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found. Please log in again.')
            return redirect('login')

        cached_otp = cache.get(f'otp_{user.id}')
        if otp == cached_otp:
            login(request, user)
            cache.delete(f'otp_{user.id}')
            if 'pending_user' in request.session:
                del request.session['pending_user']
            messages.success(request, 'Logged in successfully.')
            return redirect('profile')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return redirect('otp_login')

    return render(request, 'otp_login.html')

@no_cache_view
def signup_view(request):
    """Handle user registration with email verification."""
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        user_type = request.POST['user_type']
        phone = request.POST['phone']

        # Store form data for repopulation
        form_data = {
            'username': username,
            'email': email,
            'phone': phone,
            'user_type': user_type,
        }

        # Validate password
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup.html', {'form_data': form_data})

        if len(password) < 8 or not re.search(r'[A-Z]', password) or \
           not re.search(r'[a-z]', password) or not re.search(r'\d', password) or \
           not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            messages.error(request, 'Password must be at least 8 characters with uppercase, lowercase, number, and special character.')
            return render(request, 'signup.html', {'form_data': form_data})

        # Check for existing users
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('signup')
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('signup')

        # Create user
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            user_type=user_type,
            phone=phone
        )
        token = str(uuid.uuid4())
        cache.set(f'verify_{token}', user.id, timeout=86400)
        send_verification_email(email, token)
        messages.success(request, 'Please check your email to verify your account.')
        return redirect('login')

    return render(request, 'signup.html', {'form_data': {}})

@no_cache_view
def verify_email(request, token):
    """Verify user email with token."""
    user_id = cache.get(f'verify_{token}')
    if user_id:
        try:
            user = CustomUser.objects.get(id=user_id)
            user.is_email_verified = True
            user.is_active = True
            user.save()
            cache.delete(f'verify_{token}')
            messages.success(request, 'Email verified successfully. You can now log in.')
            return redirect('login')
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid or expired verification link.')
            return redirect('signup')
    messages.error(request, 'Invalid or expired verification link.')
    return redirect('signup')

@no_cache_view
def forgot_password(request):
    """Handle password reset request."""
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.is_email_verified:
                messages.error(request, 'Please verify your email before resetting your password.')
                return redirect('forgot_password')
            token = str(uuid.uuid4())
            cache.set(f'reset_{token}', user.id, timeout=3600)
            send_password_reset_email(email, token)
            messages.success(request, 'A password reset link has been sent to your email.')
            return redirect('login')
        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return redirect('forgot_password')
    return render(request, 'forgot_password.html')

@no_cache_view
def reset_password(request, token):
    """Handle password reset with token."""
    user_id = cache.get(f'reset_{token}')
    context = {'valid': bool(user_id)}
    if request.method == 'POST' and user_id:
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'reset_password.html', context)
        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'reset_password.html', context)

        try:
            user = CustomUser.objects.get(id=user_id)
            user.set_password(password)
            user.save()
            cache.delete(f'reset_{token}')
            messages.success(request, 'Password reset successfully. You can now log in.')
            return redirect('login')
        except CustomUser.DoesNotExist:
            messages.error(request, 'An error occurred. Please try again.')
            return redirect('forgot_password')
    return render(request, 'reset_password.html', context)

@no_cache_view
def forgot_username(request):
    """Handle username recovery."""
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.is_email_verified:
                messages.error(request, 'Please verify your email before recovering your username.')
                return redirect('forgot_username')
            otp = generate_otp()
            cache.set(f'username_otp_{user.id}', otp, timeout=600)
            send_otp_email(user.email, otp)
            request.session['pending_username_user'] = user.id
            messages.success(request, 'An OTP has been sent to your email.')
            return redirect('verify_username_otp')
        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return redirect('forgot_username')
    return render(request, 'forgot_username.html')

@no_cache_view
def verify_username_otp(request):
    """Verify OTP for username recovery."""
    if request.method == 'POST':
        otp = request.POST.get('otp')
        user_id = request.session.get('pending_username_user')
        if not user_id:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('forgot_username')
        try:
            user = CustomUser.objects.get(id=user_id)
            cached_otp = cache.get(f'username_otp_{user.id}')
            if otp == cached_otp:
                cache.delete(f'username_otp_{user.id}')
                if 'pending_username_user' in request.session:
                    del request.session['pending_username_user']
                messages.success(request, f'Your username is: {user.username}')
                return redirect('login')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('verify_username_otp')
        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found. Please try again.')
            return redirect('forgot_username')
    return render(request, 'verify_username_otp.html')

@login_required
def logout_view(request):
    """Handle user logout."""
    request.session.flush()
    logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')

@login_required
@no_cache_view
def upload_view(request):
    """Handle file upload to IPFS, MySQL, and Ethereum."""
    if request.method == 'POST':
        title = request.POST['title']
        uploaded_file = request.FILES['file']
        category = request.POST['category']
        filename = f"{request.user.username}_{title}_{uploaded_file.name}"
        file_path = BASE_DIR / 'temp' / filename

        # Save file temporarily
        os.makedirs(BASE_DIR / 'temp', exist_ok=True)
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
            logger.info(f"File written to {file_path}")

        try:
            # Check for existing file
            db_cid = db_handler.retrieve_file(filename)
            if db_cid:
                logger.warning(f"File {filename} already exists in database.")
                messages.error(request, f"File {filename} already exists. Please choose a different name or replace.")
                os.remove(file_path)
                return redirect('upload')

            # Upload to IPFS
            cid = ipfs_handler.upload_file(file_path)
            logger.info(f"File uploaded to IPFS, CID: {cid}")

            # Store in MySQL
            db_handler.store_file(filename, cid)
            logger.info(f"File stored in MySQL: {filename} -> {cid}")

            # Store on Ethereum
            contract_handler.store_file_hash(filename, cid, ABI, CONTRACT_ADDRESS)
            logger.info("File hash stored on Ethereum")

            # Save document metadata
            Document.objects.create(
                user=request.user,
                cid=cid,
                file=uploaded_file,
                filename=filename,
                title=title,
                category=category
            )
            messages.success(request, 'Document uploaded successfully')
            os.remove(file_path)
            return redirect('profile')

        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            messages.error(request, f"Error uploading file: {str(e)}")
            if os.path.exists(file_path):
                os.remove(file_path)
            return redirect('upload')

    return render(request, 'upload.html')

@login_required
@no_cache_view
def download_document(request, cid, filename):
    """Handle file download from IPFS with verification."""
    try:
        # Verify CIDs from MySQL and Ethereum
        db_cid = db_handler.retrieve_file(filename)
        eth_cid = contract_handler.retrieve_file_hash(filename, ABI, CONTRACT_ADDRESS)
        logger.info(f"Retrieved CIDs - MySQL: {db_cid}, Ethereum: {eth_cid}")

        if not db_cid or not eth_cid or db_cid != eth_cid:
            logger.error("CID mismatch or not found.")
            messages.error(request, 'File Old version of file not found or CID mismatch.')
            return redirect('profile')

        # Download file from IPFS
        file_content = ipfs_handler.get_file(db_cid)
        if not file_content:
            logger.error(f"Failed to retrieve file content for CID: {db_cid}")
            messages.error(request, 'File content could not be retrieved.')
            return redirect('profile')

        # Prepare response
        response = HttpResponse(file_content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        messages.error(request, f'Download failed: {str(e)}')
        return redirect('profile')

@login_required
@no_cache_view
def profile_view(request):
    """Display user profile with documents."""
    query = request.GET.get('q', '')
    if query:
        documents = Document.objects.filter(
            user=request.user,
            title__icontains=query
        ) | Document.objects.filter(
            user=request.user,
            category__icontains=query
        )
    else:
        documents = request.user.document_set.all()
    shared_documents = SharedDocument.objects.filter(recipient=request.user)
    return render(request, 'profile.html', {
        'documents': documents,
        'shared_documents': shared_documents
    })


@login_required
@no_cache_view
def share_document(request):
    """Handle sharing of a document with another user via email link."""
    if request.method == 'POST':
        filename = request.POST.get('filename')
        recipient_email = request.POST.get('recipient_email')

        try:
            # Retrieve document and recipient
            print("doc")
            document = Document.objects.get(filename=filename, user=request.user)
            recipient = CustomUser.objects.get(email=recipient_email)

            # Create shared document record with token
            print("shared doc")
            shared_doc = SharedDocument.objects.create(
                document=document,
                owner=request.user,
                recipient=recipient
            )

            # Generate sharing link
            print("generating share link")
            share_link = request.build_absolute_uri(
                reverse('access_shared_document', kwargs={'token': str(shared_doc.token)})
            )
            print("generated")

            # Send email to recipient
            print("sending")
            subject = f"Document Shared with You: {document.filename}"
            html_message = render_to_string('emails/share_document.html', {
                'recipient_username': recipient.username,
                'owner_username': request.user.username,
                'document_filename': document.filename,
                'share_link': share_link,
            })
            print("sending mail")
            send_mail(
                subject,
                message='',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient_email],
                html_message=html_message,
                fail_silently=False,
            )
            print("sent")
            messages.success(request, f'Document shared with {recipient_email}. A link has been sent to their email.')
            return redirect('profile')

        except CustomUser.DoesNotExist:
            messages.error(request, 'Recipient email not found.')
            return redirect('profile')
        except Document.DoesNotExist:
            messages.error(request, 'Document not found.')
            return redirect('profile')
        except Exception as e:
            logger.error(f" 1. Error sharing document: {str(e)}")
            messages.error(request, f'2. Error sharing document: {str(e)}')
            return redirect('profile')

    return render(request, 'profile.html')

@no_cache_view
def access_shared_document(request, token):
    """Handle access to a shared document via a unique token."""
    try:
        # Retrieve shared document by token
        shared_doc = get_object_or_404(SharedDocument, token=token)
        document = shared_doc.document

        # Check if the link has expired
        if shared_doc.expires_at < timezone.now():
            messages.error(request, 'This sharing link has expired.')
            return redirect('profile')

        # Check if the user is authenticated
        if not request.user.is_authenticated:
            messages.error(request, 'Please log in to access the shared document.')
            request.session['next'] = request.get_full_path()
            return redirect('login')

        # Verify user is the recipient or owner
        if request.user != shared_doc.recipient and request.user != shared_doc.owner:
            messages.error(request, 'You are not authorized to access this document.')
            return redirect('profile')

        # Verify CID from MySQL
        db_cid = db_handler.retrieve_file(document.filename)
        logger.info(f"Retrieved CID from MySQL: {db_cid}")

        if not db_cid or db_cid != document.cid:
            logger.error("CID mismatch or not found.")
            messages.error(request, 'File not found or CID mismatch.')
            return redirect('profile')

        # Download file from IPFS
        file_content = ipfs_handler.get_file(db_cid)
        if not file_content:
            logger.error(f"Failed to retrieve file content for CID: {db_cid}")
            messages.error(request, 'File content could not be retrieved.')
            return redirect('profile')

        # Prepare response
        response = HttpResponse(file_content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{document.filename}"'
        return response

    except Exception as e:
        logger.error(f"Error accessing shared document: {str(e)}")
        messages.error(request, f'Error accessing shared document: {str(e)}')
        return redirect('profile')


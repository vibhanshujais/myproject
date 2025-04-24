from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import CustomUser, Document
from django.contrib import messages
from .ipfs_module.ipfs_handler import IPFSHandler
from .eth_module.contract_handler import ContractHandler
from .db_module.db_handler import DBHandler
import json,os,re,logging
from pathlib import Path
from web3 import Web3
from django.conf import settings
from django.http import FileResponse
from .utils import generate_otp, send_otp_email, send_verification_email, send_password_reset_email
import uuid
from django.core.cache import cache
from django.views.decorators.cache import never_cache 


# Decorator to prevent caching
def no_cache_view(view_func):
    return never_cache(view_func)


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent

# with open('.config/config.json', 'r') as config_file:
#     config = json.load(config_file)

logger = logging.getLogger(__name__)
ipfs_handler = IPFSHandler()
db_handler = DBHandler("localhost", "root", "J@iswal9971", "web3")
contract_handler = ContractHandler()

abi = [
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            },
            {
                "internalType": "string",
                "name": "fileHash",
                "type": "string"
            }
        ],
        "name": "storeFile",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "fileName",
                "type": "string"
            }
        ],
        "name": "getFileHash",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "name": "fileHashes",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]
bytecode = '0x608060405234801561001057600080fd5b5061065b806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806320de1070146100465780634527525214610062578063f880680b14610092575b600080fd5b610060600480360381019061005b91906103ab565b6100c2565b005b61007c6004803603810190610077919061036a565b6100f9565b6040516100899190610498565b60405180910390f35b6100ac60048036038101906100a7919061036a565b6101af565b6040516100b99190610498565b60405180910390f35b806000836040516100d39190610481565b908152602001604051809103902090805190602001906100f492919061025f565b505050565b600081805160208101820180518482526020830160208501208183528095505050505050600091509050805461012e90610584565b80601f016020809104026020016040519081016040528092919081815260200182805461015a90610584565b80156101a75780601f1061017c576101008083540402835291602001916101a7565b820191906000526020600020905b81548152906001019060200180831161018a57829003601f168201915b505050505081565b60606000826040516101c19190610481565b908152602001604051809103902080546101da90610584565b80601f016020809104026020016040519081016040528092919081815260200182805461020690610584565b80156102535780601f1061022857610100808354040283529160200191610253565b820191906000526020600020905b81548152906001019060200180831161023657829003601f168201915b50505050509050919050565b82805461026b90610584565b90600052602060002090601f01602090048101928261028d57600085556102d4565b82601f106102a657805160ff19168380011785556102d4565b828001600101855582156102d4579182015b828111156102d35782518255916020019190600101906102b8565b5b5090506102e191906102e5565b5090565b5b808211156102fe5760008160009055506001016102e6565b5090565b6000610315610310846104eb565b6104ba565b90508281526020810184848401111561032d57600080fd5b610338848285610542565b509392505050565b600082601f83011261035157600080fd5b8135610361848260208601610302565b91505092915050565b60006020828403121561037c57600080fd5b600082013567ffffffffffffffff81111561039657600080fd5b6103a284828501610340565b91505092915050565b600080604083850312156103be57600080fd5b600083013567ffffffffffffffff8111156103d857600080fd5b6103e485828601610340565b925050602083013567ffffffffffffffff81111561040157600080fd5b61040d85828601610340565b9150509250929050565b60006104228261051b565b61042c8185610526565b935061043c818560208601610551565b61044581610614565b840191505092915050565b600061045b8261051b565b6104658185610537565b9350610475818560208601610551565b80840191505092915050565b600061048d8284610450565b915081905092915050565b600060208201905081810360008301526104b28184610417565b905092915050565b6000604051905081810181811067ffffffffffffffff821117156104e1576104e06105e5565b5b8060405250919050565b600067ffffffffffffffff821115610506576105056105e5565b5b601f19601f8301169050602081019050919050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b82818337600083830152505050565b60005b8381101561056f578082015181840152602081019050610554565b8381111561057e576000848401525b50505050565b6000600282049050600182168061059c57607f821691505b602082108114156105b0576105af6105b6565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f830116905091905056fea2646970667358221220af3788d5906206751a73fc32826eb91a7531f2cb4a7eb47fee541f22b8459ab764736f6c63430008000033'
# abi, bytecode = contract_handler.compiler_contract('eth_module/contract.sol')
contract_address = "0x6ae4a305B3768c467BeC609C3aF4488eB582639a"


def upload_file(request):
    status = ""
    if request.method == 'POST':
        uploaded_file = request.FILES['file']
        filename = f"{uploaded_file.name}"
        file_path = BASE_DIR / 'temp' / filename

        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
            print('file written')

        try: 
            file_name = str(file_path).split('/')[-1]
            db_cid = db_handler.retrieve_file(filename)
            if db_cid is not None:
                print(f"File name with {filename} already exists. Do you wish to replace file?")
                option = input("Press Y to continue, press any key to abort..")
                if option == "Y" or option == "y":
                    cid = ipfs_handler.upload_file(file_path)
                    print(f"File uploaded to IPFS, CID: {cid}")
                    os.remove(file_path)

                    #storing details in database
                    db_handler.store_dublicate(filename,cid)
                    print(f"File stored in MySQL: {filename} -> {cid}")

                    #storing detalis on ethreum
                    contract_handler.store_file_hash(filename, cid, abi, contract_address)
                    print("file hash stored on ethreum")
                else:
                    print("Operation aborted...")
            else:
                cid = ipfs_handler.upload_file(file_path)
                print(f"File uploaded to IPFS, CID: {cid}")
                os.remove(file_path)

                #storing details in database
                db_handler.store_file(filename,cid)
                print(f"File stored in MySQL: {filename} -> {cid}")

                #storing detalis on ethreum
                contract_handler.store_file_hash(filename, cid, abi, contract_address)
                print("file hash stored on ethreum")
                status = "File uploaded successfully"               

        except Exception as e:
            return HttpResponse(f"Error uploading file {e}")
    return redirect('profile')
    return render(request, 'app1/upload.html',{'status':status})
    
    # Save file temporarily to disk
    """ temp_path = f"/tmp/{file_name}"
    with open(temp_path, 'wb+') as temp_file:
        for chunk in file_obj.chunks():
            temp_file.write(chunk)

    # Check if file exists in database
    db_cid = db_handler.retrieve_file(file_name)
    if db_cid is not None and not replace:
        print(f"File name {file_name} already exists. Skipping upload.")
        os.remove(temp_path)
        return None

    # Upload to IPFS
    cid = ipfs_handler.upload_file(temp_path)
    print(f"File uploaded to IPFS, CID: {cid}")

    # Store in MySQL
    if db_cid and replace:
        db_handler.store_dublicate(file_name, cid)
    else:
        db_handler.store_file(file_name, cid)
    print(f"File stored in MySQL: {file_name} -> {cid}")

    # Store on Ethereum
    contract_handler.store_file_hash(file_name, cid, abi, contract_address)
    print("File hash stored on Ethereum")

    # Clean up temporary file
    os.remove(temp_path)
    return cid """

#def upload_file(file_path):
    file_name = file_path.split('/')[-1]
    db_cid = db_handler.retrieve_file(file_name)
    if db_cid is not None: #if file with same name exists in db, choose to replace or abort
        print(f"File name with {file_name} already exists. Do you wish to replace file?")
        option = input("Press Y to continue, press any key to abort..")
        if option == "Y" or option == "y":
            cid = ipfs_handler.upload_file(file_path)
            print(f"File uploaded to IPFS, CID: {cid}")

            #storing details in database
            db_handler.store_dublicate(file_name,cid)
            print(f"File stored in MySQL: {file_name} -> {cid}")

            #storing detalis on ethreum
            contract_handler.store_file_hash(file_name, cid, abi, contract_address)
            print("file hash stored on ethreum")
        else:
            print("Operation aborted...")
    else:
        cid = ipfs_handler.upload_file(file_path)
        print(f"File uploaded to IPFS, CID: {cid}")

        #storing details in database
        db_handler.store_file(file_name,cid)
        print(f"File stored in MySQL: {file_name} -> {cid}")

        #storing detalis on ethreum
        contract_handler.store_file_hash(file_name, cid, abi, contract_address)
        print("file hash stored on ethreum")


def home(request):
    return render(request, 'base.html')

@no_cache_view
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        if not username or not password:
            messages.error(request, 'Username and password are required.')
            return redirect('login')

        # Rate limiting: max 5 attempts per IP in 5 minutes
        ip = request.META.get('REMOTE_ADDR')
        attempts_key = f'login_attempts_{ip}'
        attempts = cache.get(attempts_key, 0)
        if attempts >= 5:
            messages.error(request, 'Too many login attempts. Please try again in 5 minutes.')
            return redirect('login')
        try:
            user = authenticate(request, username=username, password=password)
        except Exception as e:
            print(f"Authentication error: {str(e)}")
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
        cache.set(f'otp_{user.id}', otp, timeout=600)  # 10-minute validity
        send_otp_email(user.email, otp)
        request.session['pending_user'] = user.id
        return redirect('otp_login')

    return render(request, 'login.html')

@no_cache_view
def otp_login(request):
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
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.is_email_verified:
                messages.error(request, 'Please verify your email before resetting your password.')
                return redirect('forgot_password')
            token = str(uuid.uuid4())
            cache.set(f'reset_{token}', user.id, timeout=3600)  # 1-hour validity
            send_password_reset_email(email, token)
            messages.success(request, 'A password reset link has been sent to your email.')
            return redirect('login')
        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return redirect('forgot_password')
    return render(request, 'forgot_password.html')

@no_cache_view
def forgot_username(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.is_email_verified:
                messages.error(request, 'Please verify your email before recovering your username.')
                return redirect('forgot_username')
            otp = generate_otp()
            cache.set(f'username_otp_{user.id}', otp, timeout=600)  # 10-minute validity
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
    if request.method == 'POST':
        otp = request.POST.get('otp')
        user_id = request.session.get('pending_username_user')
        if not user_id:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('forgot_username')
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found. Please try again.')
            return redirect('forgot_username')
        
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
    return render(request, 'verify_username_otp.html')


@no_cache_view
def reset_password(request, token):
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
def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        user_type = request.POST['user_type']
        phone = request.POST['phone']

        # Store form data to repopulate fields (excluding passwords)
        form_data = {
            'username': username,
            'email': email,
            'phone': phone,
            'user_type': user_type,
        }

        # Validate confirm password
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup.html', {'form_data': form_data})

        # Validate strong password
        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'signup.html', {'form_data': form_data})
        if not re.search(r'[A-Z]', password):
            messages.error(request, 'Password must contain at least one uppercase letter.')
            return render(request, 'signup.html', {'form_data': form_data})
        if not re.search(r'[a-z]', password):
            messages.error(request, 'Password must contain at least one lowercase letter.')
            return render(request, 'signup.html', {'form_data': form_data})
        if not re.search(r'\d', password):
            messages.error(request, 'Password must contain at least one number.')
            return render(request, 'signup.html', {'form_data': form_data})
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            messages.error(request, 'Password must contain at least one special character (e.g., !@#$%).')
            return render(request, 'signup.html', {'form_data': form_data})

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('signup')
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('signup')
        
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            user_type=user_type,
            phone=phone
        )
        #login(request, user)
        token = str(uuid.uuid4())
        cache.set(f'verify_{token}', user.id, timeout=86400)  # 24-hour validity
        send_verification_email(email, token)
        messages.success(request, 'Please check your email to verify your account.')
        return redirect('login')
    return render(request, 'signup.html',{'form_data':{}})




def verify_email(request, token):
    user_id = cache.get(f'verify_{token}')
    if user_id:
        user = CustomUser.objects.get(id=user_id)
        user.is_email_verified = True
        user.is_active = True
        user.save()
        cache.delete(f'verify_{token}')
        messages.success(request, 'Email verified successfully. You can now log in.')
        return redirect('login')
    messages.error(request, 'Invalid or expired verification link.')
    return redirect('signup')

@login_required
def logout_view(request):
    request.session.flush()
    logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')


@login_required
@no_cache_view
def upload_view(request):
    if request.method == 'POST':
        title = request.POST['title']
        file = request.FILES['file']
        category = request.POST['category']
        file_name = f"{request.user.username}_{title}_{file.name}"
         
    status = ""
    if request.method == 'POST':
        uploaded_file = request.FILES['file']
        filename = f"{uploaded_file.name}"
        file_path = BASE_DIR / 'temp' / filename
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
            print('file written')
        try: 
            file_name = str(file_path).split('/')[-1]
            db_cid = db_handler.retrieve_file(filename)
            if db_cid is not None:
                print(f"File name with {filename} already exists. Do you wish to replace file?")
                option = input("Press Y to continue, press any key to abort..")
                if option == "Y" or option == "y":
                    cid = ipfs_handler.upload_file(file_path)
                    print(f"File uploaded to IPFS, CID: {cid}")
                    os.remove(file_path)

                    #storing details in database
                    db_handler.store_dublicate(filename,cid)
                    print(f"File stored in MySQL: {filename} -> {cid}")

                    #storing detalis on ethreum
                    contract_handler.store_file_hash(filename, cid, abi, contract_address)
                    print("file hash stored on ethreum")
                else:
                    print("Operation aborted...")
            else:
                cid = ipfs_handler.upload_file(file_path)
                print(f"File uploaded to IPFS, CID: {cid}")
                os.remove(file_path)

                #storing details in database
                db_handler.store_file(filename,cid)
                print(f"File stored in MySQL: {filename} -> {cid}")

                #storing detalis on ethreum
                contract_handler.store_file_hash(filename, cid, abi, contract_address)
                print("file hash stored on ethreum")
                status = "File uploaded successfully"               

        except Exception as e:
            return HttpResponse(f"Error uploading file {e}")

        if cid is None:
            messages.error(request, 'File upload aborted due to existing file name.')
            return redirect('upload')
        print(cid)
        document = Document.objects.create(
            user=request.user,
            cid=cid,
            file=file,
            filename=filename,
            title=title,
            category=category
        )
        messages.success(request, 'Document uploaded successfully')

        return redirect('profile')
    return render(request, 'upload.html')


@login_required
@no_cache_view
def download_document(request,cid, filename):
    cid = db_handler.retrieve_file(filename)
    print(f"CID retrieved from mySql: {cid}")

    cid2 = contract_handler.retrieve_file_hash(file_name=filename, abi=abi, contract_address= contract_address)
    print(f"cid1 = {cid}\ncid2 = {cid2}")
    
    #match cid from smartcontract and database
    if (cid and cid2) and (cid == cid2):
        file_content = ipfs_handler.get_file(cid)
        response = HttpResponse(file_content, content_type = 'application/octet-stream')
        # safe_file_name = quote(file_name)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        print("file not found in mysql")


    #document = Document.objects.filter(user=request.user, filename=filename).first()
    print(document)
    if not document:
        messages.error(request, 'Document not found.')
        return redirect('profile')

    temp_dir = Path(settings.BASE_DIR / 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    safe_filename = re.sub(r'[^\w\-\.]', '_', filename)
    if '.' in filename and not safe_filename.endswith(filename.split('.')[-1]):
        safe_filename += '.' + filename.split('.')[-1]
    output_path = temp_dir

    try:
        #from .main import ipfs_handler, db_handler, contract_handler
        logger.info(f"Retrieving CID for filename: {filename}")
        db_cid = db_handler.retrieve_file(filename)
        print(db_cid+" dbcid")
        eth_cid = contract_handler.retrieve_file_hash(filename,abi,contract_address)
        print(eth_cid)
        print("cid fetched")
        if db_cid != eth_cid:
            print("error")
            messages.error(request, 'CID mismatch. Document may have been tampered.')
            return redirect('profile')
        
        logger.info(f"Downloading file with CID {db_cid} to {output_path}")
        #ipfs_handler.get_file(db_cid, output_path)
        print("file")
        file_content = ipfs_handler.get_file(db_cid)
        
        print("file content :")
        response = HttpResponse(file_content, content_type = 'application/octet-stream')
        # safe_file_name = quote(file_name)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

        """ with open(output_path, 'rb') as f:
            content = f.read(100)  # Read first 100 bytes
            if content.decode('utf-8', errors='ignore').strip() == db_cid:
                logger.error(f"Downloaded file {output_path} contains CID {db_cid}")
                messages.error(request, 'Downloaded file contains CID instead of content.')
                return redirect('profile') """
        print("response")
        logger.info(f"Serving file {output_path} as {filename}")
        #response = FileResponse(open(output_path, 'rb'), as_attachment=True, filename=filename)
        print("hi")
        document = get_object_or_404(Document, id=15, user=request.user)
        print(document,"hello")
        file_path = document.file.path
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename="{document.file.name.split("/")[-1]}"'
            return response
        #return response
        return response
    except PermissionError as e:
        messages.error(request, f'Permission error accessing file: {str(e)}. Please try again.')
        return redirect('profile')
    except Exception as e:
        messages.error(request, f'Download failed: {str(e)}')
        return redirect('profile')
    """ finally:
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except PermissionError:
            print(f"Failed to delete {output_path}: Permission denied") """

    print("hi")
    document = get_object_or_404(Document, filename=filename, user=request.user)
    print(document)
    file_path = document.file.path
    with open(file_path, 'rb') as file:
        response = HttpResponse(file.read(), content_type="application/octet-stream")
        response['Content-Disposition'] = f'attachment; filename="{document.file.name.split("/")[-1]}"'
        return response
    
    cid = db_handler.retrieve_file(filename)
    print(f"CID retrieved from mySql: {cid}")

    cid2 = contract_handler.retrieve_file_hash(file_name=filename, abi=abi, contract_address= contract_address)
    print(f"cid1 = {cid}\ncid2 = {cid2}")

    #match cid from smartcontract and database
    if (cid and cid2) and (cid == cid2):
        file_content = ipfs_handler.get_file(cid,"download")
        response = HttpResponse(file_content, content_type = 'application/octet-stream')
        # safe_file_name = quote(file_name)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        print("file not found in mysql")


@login_required
@no_cache_view
def profile_view(request):
    query = request.GET.get('q', '')
    if query:
        documents = Document.objects.filter(
            user=request.user
        ).filter(
            documents.filter(title__icontains=query) | documents.filter(category__icontains=query)
        )
    else:
        documents = request.user.document_set.all()
    return render(request, 'profile.html', {'documents': documents})


@login_required
@no_cache_view
def share_document(request):
    if request.method == 'POST':
        filename = request.POST.get('filename')
        recipient_email = request.POST.get('recipient_email')
        try:
            recipient = CustomUser.objects.get(email=recipient_email)
            document = Document.objects.get(filename=filename, user=request.user)
            
            # Verify ownership on blockchain
            owner = contract.functions.getFileOwner(filename).call()
            if owner.lower() != request.user.eth_address.lower():
                messages.error(request, 'You are not the owner of this file.')
                return redirect('profile')

            # Share document via smart contract
            tx = contract.functions.shareDocument(filename, recipient.eth_address).buildTransaction({
                'from': request.user.eth_address,
                'nonce': w3.eth.getTransactionCount(request.user.eth_address),
                'gas': 100000,
                'gasPrice': w3.toWei('20', 'gwei')
            })
            signed_tx = w3.eth.account.signTransaction(tx, private_key=settings.USER_PRIVATE_KEY)
            tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
            w3.eth.waitForTransactionReceipt(tx_hash)

            messages.success(request, f'Document shared with {recipient_email}')
            return redirect('profile')
        except CustomUser.DoesNotExist:
            messages.error(request, 'Recipient email not found.')
            return redirect('profile')
        except Document.DoesNotExist:
            messages.error(request, 'Document not found.')
            return redirect('profile')
        except Exception as e:
            messages.error(request, f'Error sharing document: {str(e)}')
            return redirect('profile')
    return render(request, 'share_document.html')

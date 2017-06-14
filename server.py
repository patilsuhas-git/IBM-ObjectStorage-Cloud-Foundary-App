import swiftclient
import os
import sys
import re
from bottle import route, run, request, template, redirect, response
from keystoneclient import client
from Crypto import Random
from Crypto.Cipher import AES

key = #Type any random string as key.
containerName = 'YOURCONTAINERNAME'                                        #Container name.
passphrase = ''                                                           #Passphrase for encrytion and decryption purpose.
filesCloudStorage = []                                                          #Array to store all the files bject from IBMBluemix
STORE_TO_CLOUD = 'Store to Cloud'
DOWNLOAD_BUTTON = 'Download'
DELETE_BUTTON = 'Delete'
SUBMIT_ATTR = 'submit'
INDEX_DIR = 'static/index.html'
CHECK_STR = 'check'
SAVE_PATH = 'YOURLOCALMACHINEPATHWHEREYOUWANTTOSAVE'

#Service credentials from Object Storage connection.
credentials = {
                "auth_url": "YOURAUTHURL",
                "project": "YOURPROJECTNAME",
                "projectId": "YOURPROJECTID",
                "region": "YOURREGION",
                "userId": "YOURUSERID",
                "username": "YOURUSERNAME",
                "password": "YOURPASSWORD",
                "domainId": "YOURDOMAINID",
                "domainName": "YOURDOMAINNAME",
                "role": "YOURROLE"
              }

CC6331_OBST_conn = swiftclient.Connection(key = credentials['password']
                                            , authurl = credentials['auth_url'] + "/v3"
                                            , auth_version = '3'
                                            , os_options = {"project_id" : credentials['projectId']
                                                            , "user_id" : credentials['userId']
                                                            , "regional_name" : credentials['region']
                                                            }
                                        )

#Here we are adding a new container to the CloudStorage-OBST-6331.
CC6331_OBST_conn.put_container(containerName)

#POST method
@route('/', method="POST")
def uploadDownloadFile():
    if(request.forms[SUBMIT_ATTR] == STORE_TO_CLOUD) :
        name = request.files.getall('datafile')
        for i in name :
            i.save(SAVE_PATH+i.filename)

        names = [i.filename for i in name]
        totaluploadedsp = 0

        for filename in names :
            totaluploadedsp += getSize(SAVE_PATH+filename)

        if (totaluploadedsp < 1000000) :                            #To check if the total size of all uploading files is less that 10MB
            for filename in names:
                if(getSize(SAVE_PATH+filename) < 1000000) :        #To check if uploading file is less than 1 MB.
                    encrypt_file(SAVE_PATH+filename, key)
                    with open(SAVE_PATH+filename+".enc", 'rb') as uploadfile:
                        CC6331_OBST_conn.put_object(containerName, filename+".enc", contents=uploadfile.read(), content_type='')
                        os.remove(SAVE_PATH+filename+".enc")
                        os.remove(SAVE_PATH+filename)
        redirect('/')
    elif (request.forms[SUBMIT_ATTR] == DOWNLOAD_BUTTON) :
        list_of_files = request.forms.getlist(CHECK_STR)
        # print list_of_files
        for fileName in list_of_files :
            downloadedFileObject = CC6331_OBST_conn.get_object(containerName, fileName)
            with open(SAVE_PATH+fileName, 'w') as localCopy:
                localCopy.write(downloadedFileObject[1])
            decrypt_file(SAVE_PATH+fileName, key)
            with open(SAVE_PATH+fileName[:-4], 'r') as dfile:
                response.body = dfile.read()
                response.headers["Content-Disposition"] = "attachment; filename="+SAVE_PATH+fileName
                response.headers["Cache-Control"] = "must-revalidate"
                response.headers["Pragma"] = "must-revalidate"
                response.headers["content_type"] = "application/txt"
                os.remove(SAVE_PATH+fileName)
        return response
    elif (request.forms[SUBMIT_ATTR] == DELETE_BUTTON) :
        list_of_files = request.forms.getlist(CHECK_STR)
        for fileName in list_of_files :
            CC6331_OBST_conn.delete_object(containerName, fileName)
        redirect('/')

#Default GET method.
@route('/')
def index():
    global filesCloudStorage
    filesCloudStorage = []
    for data in CC6331_OBST_conn.get_container(containerName)[1]:
        filesCloudStorage.append(data)
    return template(INDEX_DIR, filesCloudStorage=filesCloudStorage)

#"Encrytion/Decrytion logic taken from : http://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes"
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_path, key):
    # encrypted_file
    with open(file_path, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_path + ".enc", 'wb') as encrypted_file :
        encrypted_file.write(enc)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_path[:-4], 'wb') as fo:
        fo.write(dec)
        decrypted_file = fo

def getSize(fileobject):
    statinfo = os.stat(fileobject)
    return statinfo.st_size

PORT = int(os.getenv('PORT', '5050'))
HOST = str(os.getenv('VCAP_APP_HOST', '0.0.0.0'))
run(host=HOST, port=PORT)

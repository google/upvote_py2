Library to make it easier to use cloud key management api from App Engine.

Provides Encript and Decript wrappers in cloud_kms.py and
EncryptedBlobProperty to be used in an ndb model. See module docstrings for
detailed usage.

Before you use this you need to:

1.  (Enable API in cloud console for your
    project)[https://cloud.google.com/kms/docs/quickstart]
1.  (Create encryption key.)[https://cloud.google.com/kms/docs/creating-keys]
1.  (Your App Engine service account has to be able access the
    API.)[https://cloud.google.com/kms/docs/iam]

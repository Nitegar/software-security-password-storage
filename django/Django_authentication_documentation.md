# **Django authentication**

Django is a Python web framework. Its built-in authentication system provides reusable components for managing users and checking their passwords.



Instead of writing every authentication function yourself, you use Django's existing components and configure them to meet the requirements of your assignment.



#### **Requirement | Django's contribution**

Secure password storage -> Configurable password hashers

Password verification -> authenticate() and check\_password()

Password length	-> Built-in minimum-length validator

Password blocklist -> Common-password validator

Rate limiting	-> Not guaranteed by basic authentication

Password expiration -> No automatic policy required



##### **Important poitns**

*-> Django supports password hashers, including Argon2. You need to install and configure the Argon2 support and verify the settings.*

*-> Django uses the PBKDF2 algorithm with a SHA256 hash, a password stretching mechanism recommended by NIST.*


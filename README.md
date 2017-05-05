# A Python console app - TOTP (2FA) Token Manager with encrypted file storage

This app outputs time-based 2FA tokens including the number of remaining seconds.

## Example output

    ID     TITLE       TOKEN
    1:     Google      437285    Remaining Secs: 25
    2:     Hotmail     783345    Remaining Secs: 25
    3:     Github      637234    Remaining Secs: 25

This app requires the 2FA Base32 secret text which is available (along with a QR code) when you setup 2FA with an application.

Encryption: AES (MODE_CBC) with HMAC authentication based on https://gist.github.com/jbtule/4336842

The encrypted data file is compatible with a .NET core cross-platform console app at: https://github.com/bifter/totp-manager-dotnetcore

The data file is an encrypted json file containing the totp data.

## Setup
1. Update the PATH_TO_SHARED_DATAFILE variable to the path you want the data file to be stored in.
2. Add an initial totp item using: {password to encrypt/decrypt the data file } -a {name of app i.e. 'Google'} {2FA Base32 secret} [Optional {Number of totp digits (defaults to 6)}]

## Basic usage
* To view totp tokens: {password}
* Add an item: {password to encrypt/decrypt the data file } -a {name of app i.e. 'Google'} {Base32 secret text} [Number of totp digits (defaults to 6)]
* Edit item: {password} -u -id {ID of item} [Optional -title {Name of app}] [Optional -secret {2FA Base32 secret}] [Optional -digits {Number of digits}]
* Remove an totp item:  {password} -del -id {ID of app - ID is shown in the list}
* Display unencrypted totp data i.e. 2FA secrets etc: {password} -d
* Update password: {password} -pu {new password}
* See help: -h

## Source
Source code can be obtained with

    git clone --recursive https://github.com/bifter/totp-manager-python

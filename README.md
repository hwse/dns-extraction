# DNS File Extraction

## Message Types

ID relates to the ID field used in DNS messages

### File Announcement

Announce the transmission of a new file.
The message contains:

* ID: 0
* Host Label (Label of the host that sent the file, must be unique if multiple clients exist)
* Random Number: Random number to avoid duplicate announcements
* File Name

Response: 
* ID: 0
* next ID: client must use this ID for first Data Message
* Random Number: same as in announcements

### Data Message

Transmit contents of the file.
The message contains:

* ID: next ID of previous message
* Segments of the file

Response: 
* ID: same as request
* next ID: client must use this ID for first Data Message

### Final Message

Signal the end of transmission.

The message contains:
* ID: 1
* 

## Example transmission

1. Client sends Announcement:
    * File Name: super-secret.txt
    * Host Label: database-server 
    * first data message: 1
    * last data message: 2
2. Server responds:
    * Confirm announcement
    * File id: 1
3. Client sends Data Message
    * File id: 1
    * 
    * Segments: "password="
4. Server confirms 

## TODO

* Checksum (UDP or custom) to resend data in case of transmission error
* Compression
* Encryption
* Delays to hide in normal dns traffic
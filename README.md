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
* random number sent by the client in announcement

## Example transmission

1. Client sends Announcement:
    * File Name: super-secret.txt
    * Host Label: database-server 
    * Random Number: 48309
2. Server responds:
    * Confirm announcement
    * Random Number: 48309
    * Next Id for the client to use: 2
3. Client sends Data Message
    * Id: 2
    * Segments: "password="
4. Server confirms 
    * Acknowledge last data message
    * Next Id for the client to use: 3
5. Client send Data Message
    * Id: 3
    * Segments: "password123"
6. Server confirms 
    * Acknowledge last data message
    * Next Id for the client to use: 4
7. Client send Finish message
    * id: 4
    * random nr: 48309
8. Server confirms that transmission finished
    * random nr: 48309

## TODO

* Checksum (UDP or custom) to resend data in case of transmission error
* Compression
* Encryption
* Delays to hide in normal dns traffic
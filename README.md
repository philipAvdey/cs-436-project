# cs-436-project
computer security, semester project. cryptographic keys vs ddos attacks.

Tasks todo:

- [ IN PROGRESS ] Create server skeleton
INSTRUCTIONS for getting the server running: 
1. Disable Airplay Receiver 
    - because we are using port 5000 to run the server we need it to be free
    - if you are on Max 5000 port is used for Airdrop Airplay etc.
    - Must Turn Off
        - Settings -> General -> Airdrop and Handoff -> Turn off Airplay Reciever
2. install flask 
    - run: pip install flask requests
    - note: you might also need to run pip install
2. Run the Server
    - Open a temrinal for the server and run: python src/server.py
3. Wait for successful running server 
    -*Debugger is active
    - should see some get and post messages along with an IP for each request
4. Open a seperate client terminal 
    - run: python src/client.py

NOTE: replace maxgulart /Users/maxgulart/SecurityProject with however you are storing the folder
- [ ] Create endpoints
- [ ] Create RSA encryption functionality on the endpoints; encrypt, decrypt, sign, verify (?)
- [ ] Create AES encryption functionality on the endpoints
- [ ] Potentially make a hybrid of both?
- [ ] Create a script to launch attack against server
- [ ] Create functionality to measure server performance under stress for all cryptographic operations

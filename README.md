This program will go through the entire Microsoft OAuth process with a Python Web App.

To run it, you'll want to run app_replica.py.
The web app will then open on localhost:5000.
Go there and sign in with an Xbox account.

To see all the acquired tokens and data, check the printed statements in the terminal. You can see the authorization code, access token, user token, x token, and then various bits of user info such as achievements, friends list, and stats.

(If you wish to run the program with a certificate as your form of client credential from Azure Active Directory as opposed to the client secret by default, you'll have to run the program via "python app_replica.py --cert" in the terminal).

For an overview of the OAuth process with Microsoft with a Python Web App, check out this presentation: 
https://docs.google.com/presentation/d/1QM2HVGmp5IYpR6xuj1IAo621KCLOsKi2tWxQC5UTN3U/edit?usp=sharing

Further explanations:

Registering App on Azure: https://drive.google.com/file/d/1vLMlg_rynCVwClS2DvpADhJfkEhbd1XA/view?usp=sharing

Access Token w/ Client Secret: https://drive.google.com/file/d/1XpapmTPih6VpCbzr45bXIseeXJQDIBIp/view?usp=sharing

Access Token w/ Certificate: https://drive.google.com/file/d/1ySrHWjVkCj3x-Rt1Eu8Acp4wohZOLajU/view?usp=sharing

User Token: https://drive.google.com/file/d/1LkqZfMdCl56VyLLnv_qALPaR4UD0iZ82/view?usp=sharing

X Token: https://drive.google.com/file/d/1G050oyxrcCp4Vrar2b76Qz0tw2ClD6yO/view?usp=sharing

Friends List: https://drive.google.com/file/d/17HBlEOP6tLlYKIDnMCZaxUbwNBPVM5T8/view?usp=sharing

Achievements: https://drive.google.com/file/d/1baJXrQQRR4PFhYMSlEs2_xFxx9zxgCFG/view?usp=sharing

Stats: https://drive.google.com/file/d/1P0cHx12ZwJ2CXpkkKAZj7i-YEQOacX_N/view?usp=sharing

# Padlock 🔒
Padlock is an end-to-end encrypted password manager. It doesn't require a master password thanks to public-private key authentication.

## Features ✨
- End-to-end encrypted.
- No master password.
- Easy to deploy. Uses a SQLite database for storage.
- Clean and easy to use interface.

## Tech stack ⚙
- Python 3: For runtime
- Cryptography.io Hazmat Layer: For cryptography requiremeents
- SQLite: For storage
- Flask: For web framework
- TailwindCSS: For styling
- Jinja2: For UI pages, layouts, and components

## Setup Locally 💻
2 simple steps

### 1. Install Dependencies
First install all the `python` dependencies:
```bash
pip install -r requirements.txt
```
Next install the needed `node` dependencies used during development. These are not included in production, but are helpful during local development:
```bash
npm install
```

### 2. Start the server
To start the server, cd to the root directory and run the `app.py` file:
```bash
python app.py
```

## Setup for Production
### 1. Build thee docker image
Inside the root directory is a `dockrfile`. This can be used to quickly provision a container to run padlock in production docker environment. Just run the command:
```bash
docker build -t padlock-image .
```
### 2. Run the docker image
Run the container on port `5000` and setup the `MASTER_PASSWORD` env. This variable is used on the "Danger Zone" page to ensure only authorized admins can delete users stored on the instance.
```bash
docker run -p 127.0.0.1:5000:5000 --env MASTER_PASSWORD=somepassword --name padlock-container -it padlock-image
```

## Scripts for Local Development
### `format`
`npm run format` uses prettier to format every `html` on the codebase.
### `tailwind:build`
`npm run tailwind:build` uses `tailwind` (the CSS framework we're using) to export all the CSS utilities being used on the codebase. 



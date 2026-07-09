ok/
├── Dockerfile              (updated: nginx now proxies /api and /admin to backend)
├── docker-compose.yml      (new: runs nginx + backend together)
├── .gitignore              (new: keeps secrets and the database out of git)
├── nginx/
│   └── nginx.conf          (new: reverse proxy config)
├── backend/
│   ├── app.py               Flask app (submissions, resources, admin)
│   ├── encryption.py        encrypts sensitive fields before storing
│   ├── resources.json       Nigeria / Spain / Global crisis resource directory
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example         copy this to backend/.env and fill in real values
└── my-site/
    └── community.html       (updated: real submit + live country resources)

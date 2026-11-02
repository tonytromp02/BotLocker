# BotLocker project page

A static, dependency-free page for BotLocker: what it is, the manifest, how it works, and how to deploy it. It uses the same colours and rounded corners as the dashboard.

Files:

- `index.html`: the content
- `style.css`: the styling
- `script.js`: small enhancements (scroll reveal, active nav, mobile menu, copy buttons). The page works without it.

The page makes no requests to other sites. It has no CDN, no web fonts, and no analytics.

## Preview locally

```sh
cd webpage
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## Deploy

Copy the folder to any static host:

- **GitHub Pages:** publish the `webpage/` folder, or copy its contents to a `docs/` folder.
- **Cloudflare Pages:** build command none, output directory `webpage`.
- **Anything else:** upload the three files.

Before publishing, decide the license. The footer says "License to be decided".

## Run with Docker

The compose file builds the `botlocker-webpage` image from the `Dockerfile` (nginx, static files, strict Content-Security-Policy) and serves it on port 8090:

```sh
cd webpage
docker compose up -d --build        # open http://localhost:8090
WEBPAGE_PORT=8080 docker compose up -d   # another host port
docker compose down
```

The container runs read-only, with a healthcheck. The "Read the docs" button links to `../README.md`, which only resolves when the folder is opened from the repository, not inside the container.

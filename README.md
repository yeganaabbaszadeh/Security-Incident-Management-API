# Security Incident Management API

A small **Flask-RESTful API** for managing **security incidents**, designed for:

- Class projects
- Demonstrating / testing **OWASP Top 10 Web Application Security Risks**
- Practicing secure coding patterns with Flask, SQLAlchemy, and PostgreSQL

It also includes **automatic PostgreSQL database creation in Python**.

---

## Project Structure

```text
.
├── app.py          # Flask app, routes, CLI command, auto DB creation
├── auth.py         # Authentication helpers (tokens, require_auth)
├── config.py       # Configuration (DB URL, secrets, limits)
├── models.py       # SQLAlchemy ORM models (User, AuthToken, Incident)
├── resources.py    # API endpoint resources
├── requirements.txt
└── README.md
```

## API Endpoints
### Authentication

POST `/auth/login`
Authenticate and receive token

POST `/auth/register`
Create a new user (admin-controlled)

### Incident Management

GET `/incidents`
List all incidents (requires token)

POST `/incidents`
Create a new incident

GET `/incidents/<id>`
Fetch incident details

PATCH `/incidents/<id>/status`
Update incident status

## Configuration & Secrets

This project follows a real-life pattern:

- **No secrets are hardcoded in the codebase.**
- All sensitive values must come from **environment variables** (or a secret manager).
- For local development, you can optionally use a `.env` file (not committed to Git).

The main required variables:

- `SECRET_KEY` – Flask secret key used for signing.
- `DATABASE_URL` – PostgreSQL connection string, e.g.  

## Postman Collections

Two collections are provided:

* Functional Tests:
[soc-incidents-api.postman_collection.json](./postman/soc-incidents-api-owasp-tests.postman_collection.json)

* Security (OWASP) Tests:
[soc-incidents-api-owasp-tests.postman_collectionjson](./postman/soc-incidents-api-owasp-tests.postman_collection.json)


Import them into Postman to test all endpoints automatically.

## Security Assessment

A full security analysis aligned with OWASP Top 10 can be found here:

📄 [OWASP-Assessment.md](./OWASP-Assessment.md) 

This includes:
* Auth tests
* Access control verification
* Injection testing
* Misconfiguration testing
* Validation behavior

## Future Improvements

* Add rate limiting
* Role-based access control (RBAC)
* Add logging and monitoring
* Deploy API behind HTTPS
* Automated dependency scanning

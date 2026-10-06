# PROJECT MERCY MEDINALEM HOSPITAL — Role-Based Hospital Management System

## Updated modules
- Secure role-based login for Administrator, Doctor, Nurse, Pharmacy, Laboratory and Reception.
- Hospital-wide patient registration: once registered, the patient identity is visible to every profession.
- Patient records are permanent; deletion is blocked at UI and server level.
- Recipient-specific profession messaging. A message addressed to Pharmacy is not delivered to Laboratory, Nurse, etc.
- **Profession expenditure register:** every profession can register patient-linked expenditure.
  - Pharmacy: Pharmacy / Drug
  - Laboratory: Medical Laboratory
  - Doctor: Doctor / Consultation
  - Nurse: Nursing Service
  - Reception: Registration / Reception
  - Administrator: General / administrative expenditure
- Automatic expenditure calculation: `unit price × quantity`.
- Central `data/expenditures.json` register and automatic hospital total on the administrator dashboard.
- Admin can review all expenditure entries and totals; other professions see their own registered expenditure.
- **Admin-controlled attendance:** administrator can mark Present, Absent, Late or Leave for every non-admin staff member by date.
- Periods are created by the administrator and visible to every profession.
- Professional hospital visual/hero artwork added to the login screen.

## Login accounts
Passwords in this delivered version are set to:

| Profession | Email | Password |
|---|---|---|
| Administrator | admin@pmmhospital.com | Admin@123 |
| Doctor | doctor@pmmhospital.com | Doctor@123 |
| Nurse | nurse@pmmhospital.com | Nurse@123 |
| Pharmacy | pharmacy@pmmhospital.com | Pharmacy@123 |
| Laboratory | lab@pmmhospital.com | Lab@123 |
| Reception | reception@pmmhospital.com | Reception@123 |

Change these passwords before using real hospital data.

## Run
Node.js 18+ is required.

```cmd
npm install
npm start
```

Open `http://localhost:3000`.

## Data files
- `data/patients.json`
- `data/appointments.json`
- `data/users.json`
- `data/attendance.json`
- `data/expenditures.json`
- `data/messages.json`
- `data/periods.json`

For production/online deployment, replace local JSON storage with a real database, HTTPS, strong passwords and a production session store.


## Admin Profession & Role Management
Administrators can create new professions from Users & Roles, select permissions, and create staff accounts assigned to any profession.


## Render PostgreSQL persistence

Set the Render Web Service environment variable `DATABASE_URL` to the PostgreSQL database Internal Database URL. The server creates an `app_data` table automatically and imports existing JSON data on first connection. Do not commit the database URL or password to Git.

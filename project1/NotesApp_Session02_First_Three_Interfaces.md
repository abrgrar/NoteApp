## Flow List

**`POST /login`**

| 1 | Browser → Flask: `POST /login (username, password)` |
| 2 | Flask → PostgreSQL: `Query (username, password)` |
| 3 | PostgreSQL → Flask: `Query result (id, username, role; empty result or query error)` |
| 4 | Flask → Browser: `HTTP 302 (Location=/, signed session cookie containing identity and JWT); on failure: HTTP 200 HTML (login form, error)` |

**`GET /login`**

| 5 | Browser → Flask: `GET /login (optional session cookie)` |
| 6 | Flask → Browser: `HTTP 200 HTML (login form)` |

**`GET /logout`**

| 7 | Browser → Flask: `GET /logout (session cookie)` |
| 8 | Flask → Browser: `HTTP 302 (Location=/login, session-clearing Set-Cookie)` |

**`GET /dashboard`**

| 9 | Student → Flask: `GET /dashboard (session cookie)` |
| 10 | Flask → PostgreSQL: `Query (session user_id)` |
| 11 | PostgreSQL → Flask: `Query result (id, grade, comment, class_name)` |
| 12 | Flask → Student: `HTTP 200 HTML (grades, comments, class names, JWT)` |

**`GET /api/notes/<id>`**

| 13 | Student → Flask: `GET /api/notes/<id> (note_id, Bearer JWT or session cookie)` |
| 14 | Flask → PostgreSQL: `Query (note_id)` |
| 15 | PostgreSQL → Flask: `Query result (id, student_id, class_id, grade, comment, student, class_name; or empty result)` |
| 16 | Flask → Student: `HTTP 200 JSON (id, student_id, class_id, grade, comment, student, class_name); HTTP 404 JSON (error) if absent` |

**`GET /teacher`**

| 17 | Teacher → Flask: `GET /teacher (session cookie)` |
| 18 | Flask → PostgreSQL: `Query (courses, grades, students)` |
| 19 | PostgreSQL → Flask: `Query results (courses; grades with student/course details; student IDs and usernames)` |
| 20 | Flask → Teacher: `HTTP 200 HTML (courses, grades, students, grade form, export links)` |

**`POST /grades`**

| 21 | Teacher → Flask: `POST /grades (session cookie, note_id, student_id, class_id, grade, comment)` |
| 22 | Flask → PostgreSQL: `Query (update grade: note_id, grade, comment; create grade: student_id, class_id, grade, comment)` |
| 23 | PostgreSQL → Flask: `Command result (write completion status)` |
| 24 | Flask → Teacher: `HTTP 302 (Location=/teacher)` |

**`GET /export.csv`**

| 25 | Teacher → Flask: `GET /export.csv (session cookie, optional class_id)` |
| 26 | Flask → PostgreSQL: `Query (optional class_id)` |
| 27 | PostgreSQL → Flask: `Query result (student, class, grade, comment)` |
| 28 | Flask → Teacher: `HTTP 200 CSV (student, class, grade, comment; filename=grades.csv)` |

**`GET /admin`**

| 29 | Admin → Flask: `GET /admin (session cookie, optional ping_result)` |
| 30 | Flask → PostgreSQL: `Query (users, classes)` |
| 31 | PostgreSQL → Flask: `Query results (users: id, username, role, teacher_id; classes: id, name, teacher_id)` |
| 32 | Flask → Admin: `HTTP 200 HTML (users, classes, user forms, ping form, optional ping_result)` |

**`POST /admin/users`**

| 33 | Admin → Flask: `POST /admin/users (session cookie; create: action, username, password, role; delete: action, user_id)` |
| 34 | Flask → PostgreSQL: `Query (create user: username, password, role; delete user: user_id)` |
| 35 | PostgreSQL → Flask: `Command result (write completion status)` |
| 36 | Flask → Admin: `HTTP 302 (Location=/admin)` |

**`POST /admin/ping`**

| 37 | Admin → Flask: `POST /admin/ping (session cookie, host)` |
| 38 | Flask → Shell/ping process: `Execute command string ("ping -c 1 " + host, shell=True)` |
| 39 | Shell/ping process → Flask: `Process result (ping output or error)` |
| 40 | Flask → Admin: `HTTP 200 HTML (ping_result)` |

**`GET /static/<path:filename>`**

| 41 | Browser → Flask: `GET /static/<path:filename> (filename, optional cache-validation headers; e.g. style.css)` |
| 42 | Flask → Static files: `Read/stat file (/app/static/<filename>)` |
| 43 | Static files → Flask: `File result (content, modification time, size)` |
| 44 | Flask → Browser: `HTTP 200 file (content, cache headers) or HTTP 304 (cache headers, no body)` |

Browser means a student, teacher, or admin browser.
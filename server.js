require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const validator = require('validator');
const disposable = require('disposable-email-domains');
const { parsePhoneNumber } = require('libphonenumber-js');
const { render } = require('ejs');
const { Pool } = require('pg');
const { error } = require('console');
const { register } = require('module');

const app = express();
const port = process.env.PORT || 3000;
const OTP_EXPIRY_MINUTES = 10;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));

async function reminderMiddleware(req, res, next) {
  const supervisorEmail = req.dbUser?.Email_Address;
  if (!supervisorEmail) return next();
  const client = await pool.connect();
  try {
    const studentsRes = await client.query(
      'SELECT * FROM students WHERE supervisor_email = $1',
      [supervisorEmail]
    );
    const studentsData = studentsRes.rows;
    const today = new Date();
    const sevenDaysAgo = new Date(today - 7 * 24 * 60 * 60 * 1000).toISOString();
    for (const student of studentsData) {
      const matNumber = student["mat_number"];
      const logsRes = await client.query(
        'SELECT remark, date FROM logs WHERE "mat_number" = $1 AND date >= $2',
        [matNumber, sevenDaysAgo]
      );
      const logs = logsRes.rows;
      if (logs.length > 0) {
        const hasRemarked = logs.some(log => log.remark && log.remark.trim() !== "");
        if (!hasRemarked) {
          const existingRes = await client.query(
            'SELECT id FROM notifications WHERE supervisor_email = $1 AND type = $2 AND student_mat_number = $3 AND created_at >= $4',
            [supervisorEmail, "unremarked_log", matNumber, sevenDaysAgo]
          );
          if (existingRes.rows.length === 0) {
            const message = `Reminder: No logs have been remarked for student ${matNumber} in the past 7 days.`;
            await client.query(
              `INSERT INTO notifications (supervisor_email, type, message, student_mat_number, read) VALUES ($1, $2, $3, $4, false)`,
              [supervisorEmail, "unremarked_log", message, matNumber]
            );
          }
        }
      }
    }
    next();
  } finally {
    client.release();
  }
}

function handleError(res, view, error, status = 500) {
  console.error(error);
  return res.status(status).render(view, { error });
}

function authenticateToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/');
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.redirect('/');
    req.tokenData = user;
    next();
  });
}

async function fetchUserJWT(req, res, next) {
  const email = req.tokenData?.email?.trim().toLowerCase();
  if (!email) return res.status(400).send("Missing user email.");

  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      'SELECT * FROM it_supervisor WHERE LOWER("Email_Address") = $1',
      [email]
    );

    if (!rows[0]) {
      client.release();
      return res.status(400).send("User not found.");
    }

    req.dbUser = {
      ...rows[0],
      Email_Address: rows[0].Email_Address.trim().toLowerCase(),
    };

    client.release();
    next();
  } catch (err) {
    client.release();
    console.error("Error in fetchUserJWT:", err);
    res.status(500).send("Internal server error.");
  }
}

function generateCalendarDays(year, month) {
  const firstDay = new Date(year, month - 1, 1);
  const lastDay = new Date(year, month, 0);
  const startDayOfWeek = firstDay.getDay();
  const totalDays = lastDay.getDate();
  const days = Array(startDayOfWeek).fill(null);
  for (let i = 1; i <= totalDays; i++) days.push(i);
  return days;
}

function isValidEmail(email) {
  return validator.isEmail(email);
}

function isDisposableEmail(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  return disposable.includes(domain);
}

function isStrongPassword(password) {
  // At least 1 uppercase, 1 lowercase, 1 digit, 8 chars
  return /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$/.test(password);
}

async function fetchUnreadNotifications(req, res, next) {
  const email = req.dbUser?.Email_Address;
  if (!email) {
    res.locals.hasUnreadNotifications = false;
    return next();
  }
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      `SELECT id FROM notifications WHERE supervisor_email = $1 AND read = false AND created_at >= $2`,
      [email, sevenDaysAgo]
    );
    res.locals.hasUnreadNotifications = rows.length > 0;
    next();
  } finally {
    client.release();
  }
}

app.get('/', (req, res) => {
  const success = req.query.success || null;
  res.render('login', { error: null, success });
});

app.post('/login', async (req, res) => {
  const email = req.body.email.trim().toLowerCase();
  const password = req.body.password;

  if (!email || !password) {
    return res.render('login', { error: 'Email and password required.', success: null });
  }

  const client = await pool.connect();
  let users;
  let error = null;

  try {
    const result = await client.query(
      'SELECT * FROM it_supervisor WHERE "Email_Address" = $1',
      [email]
    );
    users = result.rows;

    if (!users || users.length !== 1) {
      return res.render('login', { error: 'Invalid email or password.', success: null });
    }

    const user = users[0];

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) {
      return res.render('login', { error: 'Invalid email or password.', success: null });
    }

    const token = jwt.sign(
      { email: user.Email_Address, name: user.Name },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000,
      sameSite: 'strict',
    });

    res.redirect('/supervisorDashboard');

  } catch (err) {
    console.error('Database error during login:', err);
    return res.render('login', { error: 'An unexpected error occurred.', success: null });
  } finally {
    client.release();
  }
});

app.get('/supervisorDashboard', authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  try {
    const email = req.dbUser.Email_Address;

    if (process.env.NODE_ENV !== 'production') {
      console.log('👤 req.dbUser:', req.dbUser);
    }

    // Fetch students
    const studentsResult = await pool.query(
      'SELECT * FROM students WHERE LOWER(supervisor_email) = LOWER($1)',
      [email]
    );
    const studentsData = studentsResult.rows || [];
    const studentCount = studentsData.length;

    if (process.env.NODE_ENV !== 'production') {
      console.log('📚 Students Data for', email, ':', studentsData);
    }

    // Fetch notifications
    const notificationsResult = await pool.query(
      'SELECT * FROM notifications WHERE LOWER(supervisor_email) = LOWER($1) ORDER BY created_at DESC',
      [email]
    );
    const notifications = notificationsResult.rows || [];
    const notificationCount = notifications.length;

    if (process.env.NODE_ENV !== 'production') {
      console.log('🔔 Notifications for', email, ':', notifications);
    }

    res.render('supervisorDashboard', {
      user: req.dbUser,
      students: studentsData,
      studentCount,
      notificationCount,
      hasUnreadNotifications: res.locals.hasUnreadNotifications,
    });

  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).render('supervisorDashboard', {
      user: req.dbUser,
      students: [],
      studentCount: 0,
      notificationCount: 0,
      hasUnreadNotifications: res.locals.hasUnreadNotifications,
      error: 'An unexpected error occurred.',
    });
  }
});

app.get("/students", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const search = (req.query.search || "").trim().toLowerCase();
  const client = await pool.connect();
  try {
    const email = req.dbUser.Email_Address;

    const studentsResult = await client.query(
      'SELECT * FROM students WHERE supervisor_email = $1',
      [email]
    );
    const studentsData = studentsResult.rows;

    if (!studentsData) {
      console.error('Error fetching students.');
      return res.status(500).render('students', {
        user: req.dbUser,
        students: [],
        search: '',
        hasUnreadNotifications: res.locals.hasUnreadNotifications,
        error: "Unable to fetch students."
      });
    }

    res.render("students", {
      user: req.dbUser,
      students: studentsData,
      search,
      hasUnreadNotifications: res.locals.hasUnreadNotifications,
    });

  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).render('students', {
      user: req.dbUser,
      students: [],
      search: '',
      hasUnreadNotifications: res.locals.hasUnreadNotifications,
      error: "An unexpected error occurred."
    });
  } finally {
    client.release();
  }
});

app.get("/student/:matNumber", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const matNumber = req.params.matNumber;

  try {
    // Fetch student
    const studentResult = await pool.query(
      `SELECT * FROM students WHERE "mat_number" = $1 LIMIT 1`,
      [matNumber]
    );

    if (studentResult.rowCount === 0) {
      return res.status(404).send("Student not found.");
    }
    const student = studentResult.rows[0];

    // Fetch logs
    const logsResult = await pool.query(
      `SELECT * FROM logs WHERE "mat_number" = $1 ORDER BY date DESC`,
      [matNumber]
    );
    const logs = logsResult.rows;
    const latestLog = logs.length > 0 ? logs[0] : null;

    res.render("student_details", {
      user: req.dbUser,
      student,
      logs,
      latestLog,
      success: req.query.success,
      error: req.query.error,
      hasUnreadNotifications: res.locals.hasUnreadNotifications
    });
  } catch (err) {
    console.error("Error fetching student details:", err);
    res.status(500).send("Internal server error.");
  }
});

app.post("/student/:matNumber/save-remark", authenticateToken, fetchUserJWT, async (req, res) => {
  const matNumber = req.params.matNumber;
  const { remark } = req.body;

  if (!remark) {
    return res.status(400).send("Remark cannot be empty.");
  }

  const client = await pool.connect();
  try {
    // Fetch logs for the student, latest first
    const logsResult = await client.query(
      `SELECT * 
       FROM logs 
       WHERE "mat_number" = $1 
       ORDER BY date DESC 
       LIMIT 1`,
      [matNumber]
    );

    if (logsResult.rows.length === 0) {
      return res.status(404).send("No log found for this student.");
    }

    const latestLog = logsResult.rows[0];

    // Update remark for latest log
    const updateResult = await client.query(
      `UPDATE logs 
       SET remark = $1 
       WHERE id = $2`,
      [remark, latestLog.id]
    );

    if (updateResult.rowCount === 0) {
      return res.status(500).send("Error updating remark.");
    }

    res.redirect(`/student/${matNumber}?success=Remark saved successfully!`);
  } catch (err) {
    console.error("Error updating remark:", err);
    res.status(500).send("Error updating remark.");
  } finally {
    client.release();
  }
});

app.get("/student/:matNumber/logs", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
    const matNumber = req.params.matNumber;
    const client = await pool.connect();

    try {
      const studentResult = await client.query(
        `SELECT * 
         FROM students 
         WHERE mat_number = $1 
         LIMIT 1`,
        [matNumber]
      );

      if (studentResult.rows.length === 0) {
        return res.status(404).send("Student not found.");
      }

      const student = studentResult.rows[0];

      const logsResult = await client.query(
        `SELECT * 
         FROM logs 
         WHERE mat_number = $1`,
        [matNumber]
      );

      const logs = logsResult.rows;

      const logsByDate = {};
      logs.forEach((log) => {
        const dateString = new Date(log.date).toISOString().split("T")[0];
        if (log.remark && log.remark.trim() !== "") {
          logsByDate[dateString] = "remarked";
        } else {
          logsByDate[dateString] = "awaiting";
        }
      });

      const itStart = new Date(student.it_start_date);
      const itEnd = new Date(student.it_end_date);

      const year = parseInt(req.query.year) || new Date().getFullYear();
      const month = parseInt(req.query.month) || new Date().getMonth() + 1;

      const currentMonthDate = new Date(year, month - 1);
      if (
        currentMonthDate <
          new Date(itStart.getFullYear(), itStart.getMonth()) ||
        currentMonthDate > new Date(itEnd.getFullYear(), itEnd.getMonth())
      ) {
        return res.status(403).send("Month outside IT duration.");
      }

      const firstDay = new Date(year, month - 1, 1);
      const lastDay = new Date(year, month, 0);
      const totalDays = lastDay.getDate();
      const calendarDays = [];

      for (let day = 1; day <= totalDays; day++) {
        const date = new Date(year, month - 1, day);
        if (date.getDay() !== 0) {
          calendarDays.push(day);
        }
      }

      const canGoPrev =
        new Date(year, month - 2) >=
        new Date(itStart.getFullYear(), itStart.getMonth());
      const canGoNext =
        new Date(year, month) <= new Date(itEnd.getFullYear(), itEnd.getMonth());

      res.render("all_logs", {
        user: req.dbUser,
        student,
        year,
        month,
        monthName: new Date(year, month - 1).toLocaleString("default", {
          month: "long",
        }),
        calendarDays,
        logsByDate,
        canGoPrev,
        canGoNext,
        hasUnreadNotifications: res.locals.hasUnreadNotifications,
      });
    } catch (err) {
      console.error("Error fetching student logs:", err);
      res.status(500).send("Error fetching logs.");
    } finally {
      client.release();
    }
  }
);

app.get("/student/:matNumber/logs/:date", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
    const { matNumber, date } = req.params;
    const client = await pool.connect();

    try {
      const normalizedDate = new Date(date).toISOString().split("T")[0];
      const startOfDay = new Date(normalizedDate);
      const endOfDay = new Date(startOfDay);
      endOfDay.setDate(endOfDay.getDate() + 1);

      const studentResult = await client.query(
        `SELECT * 
         FROM students 
         WHERE mat_number = $1 
         LIMIT 1`,
        [matNumber]
      );

      if (studentResult.rows.length === 0) {
        return res.status(404).send("Student not found.");
      }

      const student = studentResult.rows[0];

      const logResult = await client.query(
        `SELECT * 
         FROM logs 
         WHERE mat_number = $1 
           AND date >= $2 
           AND date < $3
         LIMIT 1`,
        [matNumber, startOfDay.toISOString(), endOfDay.toISOString()]
      );

      const logData = logResult.rows[0] || null;

      return res.render("logs_for_date", {
        user: req.dbUser,
        student,
        log: logData,
        date: normalizedDate,
        success: req.query.success,
        error: req.query.error,
        hasUnreadNotifications: res.locals.hasUnreadNotifications,
      });
    } catch (err) {
      console.error("Error fetching log for date:", err);
      res.status(500).send("Error fetching log.");
    } finally {
      client.release();
    }
  }
);

app.post("/student/:matNumber/logs/:date/save-remark", authenticateToken, fetchUserJWT, async (req, res) => {
    const { matNumber, date } = req.params;
    const { remark } = req.body;
    const client = await pool.connect();

    try {
      const cleanRemark = (remark || "").trim();
      if (!cleanRemark) {
        return res.redirect(
          `/student/${matNumber}/logs/${date}?error=${encodeURIComponent(
            "Remark cannot be empty."
          )}`
        );
      }

      const startOfDay = new Date(`${date}T00:00:00Z`).toISOString();
      const endOfDay = new Date(`${date}T23:59:59Z`).toISOString();

      const logResult = await client.query(
        `SELECT * 
         FROM logs 
         WHERE mat_number = $1 
           AND date >= $2 
           AND date <= $3
         LIMIT 1`,
        [matNumber.trim(), startOfDay, endOfDay]
      );

      const log = logResult.rows[0] || null;

      if (!log) {
        console.error("Log fetch error: not found for student/date");
        return res.redirect(
          `/student/${matNumber}/logs/${date}?error=${encodeURIComponent(
            "Log not found."
          )}`
        );
      }

      const updateResult = await client.query(
        `UPDATE logs 
         SET remark = $1 
         WHERE id = $2`,
        [cleanRemark, log.id]
      );

      if (updateResult.rowCount === 0) {
        return res.redirect(
          `/student/${matNumber}/logs/${date}?error=${encodeURIComponent(
            "Error updating remark."
          )}`
        );
      }

      res.redirect(
        `/student/${matNumber}/logs/${date}?success=${encodeURIComponent(
          "Remark saved successfully!"
        )}`
      );
    } catch (err) {
      console.error("Error updating remark:", err);
      res.redirect(
        `/student/${matNumber}/logs/${date}?error=${encodeURIComponent(
          "Error updating remark."
        )}`
      );
    } finally {
      client.release();
    }
  }
);

app.get("/student/:matNumber/info", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
    const matNumber = req.params.matNumber;
    const client = await pool.connect();

    try {
      const studentResult = await client.query(
        `SELECT * 
         FROM students 
         WHERE mat_number = $1 
         LIMIT 1`,
        [matNumber]
      );

      if (studentResult.rows.length === 0) {
        return res.status(404).send("Student not found.");
      }

      const student = studentResult.rows[0];

      res.render("student_info", {
        user: req.dbUser,
        student,
        hasUnreadNotifications: res.locals.hasUnreadNotifications,
      });
    } catch (err) {
      console.error("Error fetching student info:", err);
      res.status(500).send("Error fetching student info.");
    } finally {
      client.release();
    }
  }
);

app.get("/calendar", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const { month, year } = req.query;

  const userMonth = parseInt(month) || (new Date().getMonth() + 1);
  const userYear = parseInt(year) || new Date().getFullYear();

  const monthNames = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  ];
  const calendarDays = generateCalendarDays(userYear, userMonth);

  res.render("calendar", {
    user: req.dbUser,
    calendarDays,
    month: userMonth,
    year: userYear,
    monthName: monthNames[userMonth - 1],
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.get("/notifications", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const supervisorEmail = req.dbUser.Email_Address.trim().toLowerCase();
  const client = await pool.connect();

  try {
    const result = await client.query(
      `SELECT * FROM notifications 
       WHERE LOWER(TRIM(supervisor_email)) = $1 
       ORDER BY created_at DESC`,
      [supervisorEmail]
    );

    res.render("notifications", {
      user: req.dbUser,
      notifications: result.rows,
      hasUnreadNotifications: res.locals.hasUnreadNotifications
    });
  } catch (err) {
    console.error("Failed to load notifications:", err);
    res.status(500).send("Failed to load notifications.");
  } finally {
    client.release();
  }
});

app.delete("/notifications/:id", authenticateToken, fetchUserJWT, async (req, res) => {
  const { id } = req.params;
  const supervisorEmail = req.dbUser.Email_Address.trim().toLowerCase();
  const client = await pool.connect();

  try {
    const result = await client.query(
      `DELETE FROM notifications 
       WHERE id = $1 AND LOWER(TRIM(supervisor_email)) = $2
       RETURNING id`,
      [id, supervisorEmail]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: "Notification not found or not authorized." });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Failed to delete notification:", err);
    return res.status(500).json({ success: false });
  } finally {
    client.release();
  }
});

app.delete("/notifications", authenticateToken, fetchUserJWT, async (req, res) => {
  const supervisorEmail = req.dbUser.Email_Address.trim().toLowerCase();
  const client = await pool.connect();

  try {
    const result = await client.query(
      `DELETE FROM notifications
      WHERE LOWER(TRIM(supervisor_email)) = $1
      RETURNING id`,
      [supervisorEmail]
    );

    return res.json({ 
      success: true, 
      deletedCount: result.rowCount 
    });
  } catch (err) {
    console.error("Failed to delete notifications:", err);
    return res.status(500).json({ success: false });
  } finally {
    client.release();
  }
});

app.get("/settings", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  res.render("settings", {
    user: req.dbUser,
    success: req.query.success,
    error: req.query.error,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.post("/change-password", authenticateToken, fetchUserJWT, async (req, res) => {
  let { email, currentPassword, newPassword, confirmPassword } = req.body;
  email = email.trim().toLowerCase();

  try {
    const client = await pool.connect();

    const { rows } = await client.query(
      'SELECT * FROM it_supervisor WHERE LOWER("Email_Address") = $1',
      [email]
    );

    const user = rows[0];
    if (!user) {
      client.release();
      return res.render("settings", { 
        user: req.dbUser, 
        error: "User not found.",
        hasUnreadNotifications: res.locals.hasUnreadNotifications
      });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
      client.release();
      return res.render("settings", { user: req.dbUser, error: "Current password is incorrect.", hasUnreadNotifications: res.locals.hasUnreadNotifications });
    }

    if (newPassword.length < 8) {
      client.release();
      return res.render("settings", { user: req.dbUser, error: "New password must be at least 8 characters long.", hasUnreadNotifications: res.locals.hasUnreadNotifications });
    }
    if (!isStrongPassword(newPassword)) {
      client.release();
      return res.render("settings", { user: req.dbUser, error: "Password must contain an uppercase, a lowercase, and a number.", hasUnreadNotifications: res.locals.hasUnreadNotifications });
    }
    if (newPassword !== confirmPassword) {
      client.release();
      return res.render("settings", { user: req.dbUser, error: "New passwords do not match.", hasUnreadNotifications: res.locals.hasUnreadNotifications });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await client.query(
      'UPDATE it_supervisor SET password = $1 WHERE LOWER("Email_Address") = $2',
      [hashedPassword, email]
    );

    client.release();
    res.render("settings", { user: req.dbUser, success: "Password updated successfully!", hasUnreadNotifications: res.locals.hasUnreadNotifications });

  } catch (err) {
    console.error("Error updating password:", err);
    res.render("settings", { user: req.dbUser, error: "Error updating password.", hasUnreadNotifications: res.locals.hasUnreadNotifications });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
  res.redirect("/");
});

app.get('/submit-supervisor', (req, res) => res.render('supervisorForm', { error: null }));

app.post('/submit-supervisor', async (req, res) => {
  const email_address = req.body.email_address.trim().toLowerCase();

  if (!isValidEmail(email_address)) {
    return res.render('supervisorForm', { error: 'Invalid email format.' });
  }
  if (isDisposableEmail(email_address)) {
    return res.render('supervisorForm', { error: 'Disposable emails are not allowed.' });
  }

  const client = await pool.connect();
  try {
    // Fetch supervisor
    const { rows: supervisors } = await client.query(
      `SELECT * FROM it_supervisor WHERE "Email_Address" = $1`,
      [email_address]
    );

    if (supervisors.length === 0) {
      console.error("Supervisor email fetch error: not found");
      return res.render('supervisorForm', { error: 'Email not found in supervisor records.' });
    }

    const supervisor = supervisors[0];

    if (supervisor.password) {
      console.error("Supervisor already has an account:", supervisor);
      return res.render('supervisorForm', { error: 'Account already exists. Please log in.' });
    }

    // Generate OTP + expiration using DB time
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const { rows: nowRows } = await client.query(`SELECT NOW()`);
    if (nowRows.length === 0) {
      return handleError(res, 'supervisorForm', 'Could not verify server time.');
    }

    const serverNow = nowRows[0].now;
    const expires_at = new Date(new Date(serverNow).getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

    // Upsert OTP
    await client.query(
      `INSERT INTO "OTPs" (email, otp, expires_at, temp_data)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email)
       DO UPDATE SET otp = $2, expires_at = $3, temp_data = $4`,
      [email_address, otp, expires_at.toISOString(), JSON.stringify({ email_address })]
    );

    // Send OTP email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email_address,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`,
    });

    res.redirect(`/verify-otp?email=${encodeURIComponent(email_address)}`);
  } catch (error) {
    console.error("Error in /submit-supervisor:", error);
    handleError(res, 'supervisorForm', 'Failed to send OTP.', 500);
  } finally {
    client.release();
  }
});

app.get('/verify-otp', (req, res) => {
  const email = req.query.email?.trim().toLowerCase() || '';
  const mode  = req.query.mode || 'register';
  if (!email) {
    return res.status(400).send("Missing email.");
  }
  res.render('verifyOtp', { email, error: null, mode });
});

app.post('/verify-otp', async (req, res) => {
  const email = req.body.email.trim().toLowerCase(); 
  const mode = req.body.mode || 'register';

  const enteredOtp = (req.body.otp || []).join('').trim();

  try {
    const query = 
      `SELECT * FROM "OTPs" 
      WHERE email = $1
      LIMIT 1`;

    const { rows } = await pool.query(query, [email]);
    const data = rows[0];

    if (!data) {
      return res.render('verifyOtp', { email, error: 'No OTP found for this email.', mode });
    }

    if (Date.now() > new Date(data.expires_at).getTime()) {
    return res.render('verifyOtp', { email, error: 'OTP expired.', mode });
    }

    if (data.otp !== enteredOtp) {
    return res.render('verifyOtp', { email, error: 'Incorrect OTP.', mode });
    }

  res.redirect(`/create-password?email=${encodeURIComponent(email)}&mode=${mode}`);
} catch (error) {
  res.render('verifyOtp', { email, error: 'Failed to verify OTP.', mode });
}
});

app.post('/resend-otp', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const mode = req.body.mode || 'register';

  if (!email || !isValidEmail(email)) {
    return res.status(400).send('Valid email is required to resend OTP.');
  }

  try {
    const client = await pool.connect();

    // ✅ get server time from PostgreSQL
    const { rows: timeRows } = await client.query('SELECT NOW() as now');
    const now = new Date(timeRows[0].now);

    // ✅ check if OTP already exists
    const { rows } = await client.query(
      `SELECT * FROM "OTPs" WHERE email = $1 LIMIT 1`,
      [email]
    );
    const otpEntry = rows[0];

    if (otpEntry) {
      const lastResend = otpEntry.last_resend ? new Date(otpEntry.last_resend) : null;
      const resendCount = otpEntry.resend_count || 0;

      if (resendCount >= 3) {
        if (lastResend) {
          const cooldownEnd = new Date(lastResend.getTime() + 30 * 60 * 1000);
          if (now < cooldownEnd) {
            const waitMinutes = Math.ceil((cooldownEnd - now) / 60000);

            client.release();
            return res.render('verifyOtp', {
              email,
              error: `Resend limit reached. Please try again in ${waitMinutes} minute${waitMinutes > 1 ? 's' : ''}.`,
              mode,
              resendDisabled: true,
              waitMinutes,
            });
          } else {
            // Reset resend counter after cooldown
            await client.query(
              'UPDATE "OTPs" SET resend_count = $1, last_resend = $2 WHERE email = $3',
              [0, null, email]
            );
          }
        }
      }
    }

    // ✅ generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const OTP_EXPIRY_MINUTES = 10;
    const expires_at = new Date(now.getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

    const updatedResendCount = otpEntry ? (otpEntry.resend_count || 0) + 1 : 1;
    const lastResendTimestamp = now.toISOString();

    // ✅ upsert OTP record
    await client.query(
      `INSERT INTO "OTPs" (email, otp, expires_at, temp_data, resend_count, last_resend)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (email) DO UPDATE SET
         otp = EXCLUDED.otp,
         expires_at = EXCLUDED.expires_at,
         temp_data = EXCLUDED.temp_data,
         resend_count = EXCLUDED.resend_count,
         last_resend = EXCLUDED.last_resend`,
      [email, otp, expires_at.toISOString(),
       JSON.stringify({ email_address: email }), updatedResendCount, lastResendTimestamp]
    );

    client.release();

    // ✅ send OTP via email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code (Resent)',
      text: `Your new OTP code is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`,
    });

    res.redirect(`/verify-otp?email=${encodeURIComponent(email)}&mode=${mode}&success=otp-resent`);

  } catch (error) {
    console.error('Error resending OTP:', error);
    res.status(500).send('Failed to resend OTP.');
  }
});

app.get('/create-password', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  const mode = req.query.mode || 'register';
  if (!email) {
    return res.status(400).send('Missing email.');
  }
  res.render('createPassword', { email, error: null, mode });
});

app.post('/create-password', async (req, res) => {
  const email = req.body.email.trim().toLowerCase();
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  const mode = req.body.mode || 'register';

  if (password !== confirmPassword) {
    return res.render('createPassword', { email, error: 'Passwords do not match.', mode });
  }
  if (!isStrongPassword(password)) {
    return res.render('createPassword', {
      email,
      error: 'Password must contain an uppercase letter, a lowercase letter, and a number (min 8 chars).',
      mode
    });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM "OTPs" WHERE email = $1 LIMIT 1',
      [email]
    );
    const data = rows[0];
    if (!data || !data.temp_data) {
      return res.render('createPassword', { email, error: 'No temporary data found.', mode });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const temp = data.temp_data;

    const updateResult = await pool.query(
      'UPDATE it_supervisor SET password = $1 WHERE "Email_Address" = $2',
      [hashedPassword, temp.email_address]
    );
    if (updateResult.rowCount === 0) {
      console.error("Update supervisor error: No update performed");
      return res.render('createPassword', { email, error: 'Failed to create account.', mode });
    }

    await pool.query('DELETE FROM "OTPs" WHERE email = $1', [email]);

    if (mode === 'reset') {
      return res.redirect('/?success=password-reset');
    } else {
      res.redirect('/?success=account-created');
    }
  } catch (error) {
    console.error("Error in create-password:", error);
    res.render('createPassword', { email, error: 'Server error. Please try again.', mode });
  }
});

app.get('/forgot-password', (req, res) => {
  res.render('forgotPassword', { error: null });
}); 

app.post('/forgot-password', async (req, res) => {
  const email_address = req.body.email_address.trim().toLowerCase();

  if (!isValidEmail(email_address)) {
    return res.render('forgotPassword', { error: 'Invalid email format.' });
  }
  if (isDisposableEmail(email_address)) {
    return res.render('forgotPassword', { error: 'Disposable emails are not allowed.' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM it_supervisor WHERE "Email_Address" = $1 LIMIT 1',
      [email_address]
    );
    const supervisor = rows[0];

    if (!supervisor) {
      return res.render('forgotPassword', { error: 'Email not found in supervisor records.' });
    }

    if (!supervisor.password) {
      return res.render('forgotPassword', { error: 'Account not found or not yet registered' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const OTP_EXPIRY_MINUTES = 10;
    const now = new Date();
    const expires_at = new Date(now.getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await pool.query(
      `INSERT INTO "OTPs" (email, otp, expires_at, temp_data)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO UPDATE SET
         otp = EXCLUDED.otp,
         expires_at = EXCLUDED.expires_at,
         temp_data = EXCLUDED.temp_data`,
      [email_address, otp, expires_at.toISOString(), JSON.stringify({ email_address })]
    );

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email_address,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`,
    });

    res.redirect(`/verify-otp?email=${encodeURIComponent(email_address)}&mode=reset`);
  } catch (error) {
    console.error('Error in forgot-password:', error);
    res.render('forgotPassword', { error: 'Server error. Please try again.' });
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
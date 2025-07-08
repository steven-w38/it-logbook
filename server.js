require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const validator = require('validator');
const disposable = require('disposable-email-domains');
const { parsePhoneNumber } = require('libphonenumber-js');
const { render } = require('ejs');

const app = express();
const port = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.API_KEY);
const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES || '5', 10);
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function handleError(res, view, error, status = 500) {
  console.error(error);
  return res.status(status).render(view, { error });
}

function authenticateToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/login');
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.redirect('/login');
    req.tokenData = user;
    next();
  });
}

async function fetchUserJWT(req, res, next) {
  const email = req.tokenData?.email;
  if (!email) return res.status(400).send('Missing user email.');
  const { data, error } = await supabase
    .from('it_supervisor')
    .select('*')
    .eq('Email_Address', email)
    .single();
  if (error || !data) return res.status(400).send('User not found');
  req.dbUser = data;
  next();
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

  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  
  const { data:unread, error } = await supabase.from('notifications').select('id').eq('supervisor_email', email).eq('read', false).gte('created_at', sevenDaysAgo.toISOString());
  
  if (error) {
    console.error('Error fetching notifications:', error);
    return res.status(500).send('Failed to fetch notifications.');
  }
  
  res.locals.hasUnreadNotifications = unread.length > 0;
  next();
}

async function reminderMiddleware(req, res, next) {
  const supervisorEmail = req.dbUser?.Email_Address;
  if (!supervisorEmail) return next();

  const { data: studentsData, error: studentsError } = await supabase.from("students").select("*").eq("supervisor_email", supervisorEmail);

  if (studentsError) {
    console.error("Failed to fetch students for log reminder check:", studentsError);
    return next();
  }

  const today = new Date();
  const sevenDaysAgo = new Date(today);
  sevenDaysAgo.setDate(today.getDate() - 7);

  for (const student of studentsData) {
    const matNumber = student["mat number"];

    const { data: logs, error: logsError } = await supabase.from("logs").select("remark, date").eq("mat number", matNumber).gte("date", sevenDaysAgo.toISOString());

    if (logsError|| !logs || logs.length === 0) continue;

    const hasRemarked = logs.some(log => log.remark && log.remark.trim() !== "");

    if (!hasRemarked) {
      const { data: existing } = await supabase.from("notifications").select("id").eq("supervisor_email", supervisorEmail).eq("type", "unremarked_log").eq("student_mat_number", matNumber).gte("created_at", sevenDaysAgo.toISOString());

      if (!existing || existing.length === 0) {
        const message = `Reminder: No logs have been remarked for student ${matNumber} in the past 7 days.`;

        await supabase.from("notifications").insert([{
          supervisor_email: supervisorEmail,
          type: "unremarked_log",
          message,
          student_mat_number: matNumber,
          read: false
        }]);
      }
    }
  }

  next();
}

app.get('/', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: 'Email and password required.' });
  }

  const { data: user, error } = await supabase.from('it_supervisor').select('*').eq('Email_Address', email).single();
  if (error || !user) {
    return res.render('login', { error: 'Invalid email or password.' });
  }

  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) {
    return res.render('login', { error: 'Invalid email or password.' });
  }

  const token = jwt.sign({ email: user.Email_Address, name: user.Name }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000,
    sameSite: 'strict',
  });
  res.redirect('/dashboard');
});

app.get("/dashboard", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const search = (req.query.search || "").trim().toLowerCase();

  let { data: studentsData, error: studentsError } = await supabase.from("students").select("*").eq("supervisor_email", req.dbUser.Email_Address);

  if (studentsError) {
    console.error('Error fetching students:', studentsError);
    return res.status(500).render('dashboard', {
      user: req.dbUser,
      students: [],
      search: '',
      hasUnreadNotifications: res.locals.hasUnreadNotifications,
      error: "Unable to fetch students."
    });
  }

  res.render("dashboard", {
    user: req.dbUser,
    students: studentsData,
    search,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.get("/student/:matNumber", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const matNumber = req.params.matNumber;

  const { data: student, error: studentError } = await supabase.from("students").select("*").eq("mat number", matNumber).single();
  if (studentError || !student) {
    return res.status(404).send("Student not found.");
  }

  const { data: logs, error: logsError } = await supabase
    .from("logs").select("*").eq("mat number", matNumber).order("date", { ascending: false });
  const latestLog = logs?.[0] || null;

  res.render("student_details", {
    user: req.dbUser,
    student,
    logs,
    latestLog,
    success: req.query.success,
    error: req.query.error,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.post("/student/:matNumber/save-remark", authenticateToken, fetchUserJWT, async (req, res) => {
  const matNumber = req.params.matNumber;
  const { remark } = req.body;

  if (!remark) {
    return res.status(400).send("Remark cannot be empty.");
  }

  const { data: logs, error: logsError } = await supabase.from("logs").select("*").eq("mat number", matNumber).order("date", { ascending: false });
  if (logsError || !logs?.length) {
    return res.status(404).send("No log found for this student.");
  }

  const latestLog = logs[0];
  const { error: updateError } = await supabase.from("logs").update({ remark }).eq("id", latestLog.id);
  if (updateError) {
    return res.status(500).send("Error updating remark.");
  }

  res.redirect(`/student/${matNumber}?success=Remark saved successfully!`);
});

app.get("/student/:matNumber/logs", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware,  async (req, res) => {
  const matNumber = req.params.matNumber;

  const { data: student, error: studentError } = await supabase.from("students").select("*").eq("mat number", matNumber).single();

  if (studentError || !student) {
    return res.status(404).send("Student not found.");
  }

  const { data: logs, error: logsError } = await supabase.from("logs").select("*").eq("mat number", matNumber);

  if (logsError) {
    return res.status(500).send("Error fetching logs.");
  }

  const logsByDate = {};
  logs.forEach(log => {
    const dateString = new Date(log.date).toISOString().split("T")[0];
    if (log.remark && log.remark.trim() !== "") {
      logsByDate[dateString] = "remarked";
    } else {
      logsByDate[dateString] = "awaiting";
    }
  });

  const itStart = new Date (student.it_start_date);
  const itEnd = new Date(student.it_end_date);

  const year = parseInt(req.query.year) || new Date().getFullYear();
  const month = parseInt(req.query.month) || new Date().getMonth() + 1;

  const currentMonthDate = new Date(year, month - 1);
  if (currentMonthDate < new Date(itStart.getFullYear(), itStart.getMonth()) ||
      currentMonthDate > new Date(itEnd.getFullYear(), itEnd.getMonth())) {
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

  const canGoPrev = new Date(year, month - 2) >= new Date(itStart.getFullYear(), itStart.getMonth());
  const canGoNext = new Date(year, month) <= new Date(itEnd.getFullYear(), itEnd.getMonth());

  res.render("all_logs", {
    user: req.dbUser,
    student,
    year,
    month,
    monthName: new Date(year, month - 1).toLocaleString("default", { month: "long" }),
    calendarDays,
    logsByDate,
    canGoPrev,
    canGoNext,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.get("/student/:matNumber/logs/:date", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const { matNumber, date } = req.params;

  const normalizedDate = new Date(date).toISOString().split("T")[0];
  const startOfDay = new Date(normalizedDate);
  const endOfDay = new Date(startOfDay);
  endOfDay.setDate(endOfDay.getDate() + 1);

  const { data: student, error: studentError } = await supabase.from("students").select("*").eq("mat number", matNumber).single();
  if (studentError || !student) {
    return res.status(404).send("Student not found.");
  }

  const { data: logData, error: logError } = await supabase.from("logs").select("*").eq("mat number", matNumber).gte("date", startOfDay.toISOString()).lt("date", endOfDay.toISOString()).single();

  return res.render("logs_for_date", {
    user: req.dbUser,
    student,
    log: logData,
    date: normalizedDate,
    success: req.query.success,
    error: req.query.error,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

app.post("/student/:matNumber/logs/:date/save-remark", authenticateToken, fetchUserJWT, async (req, res) => {
  const { matNumber, date } = req.params;
  const { remark } = req.body;

  const cleanRemark = (remark || "").trim();
  if (!cleanRemark) {
  return res.redirect(`/student/${matNumber}/logs/${date}?error=${encodeURIComponent("Remark cannot be empty.")}`);
  }

  const startOfDay = new Date(`${date}T00:00:00Z`).toISOString();
  const endOfDay = new Date(`${date}T23:59:59Z`).toISOString();

  const { data: logs, error: logError } = await supabase.from("logs").select("*").eq("mat number", matNumber.trim()).gte("date", startOfDay).lte("date", endOfDay);

  const log = logs && logs.length > 0 ? logs[0] : null;

  if (logError || !log) {
  console.error("Log fetch error:", logError);
  return res.redirect(`/student/${matNumber}/logs/${date}?error=${encodeURIComponent("Log not found.")}`);
  }

  const { error: updateError } = await supabase.from("logs").update({ remark: cleanRemark }).eq("id", log.id);

  if (updateError) {
  return res.redirect(`/student/${matNumber}/logs/${date}?error=${encodeURIComponent("Error updating remark.")}`);
}

  res.redirect(`/student/${matNumber}/logs/${date}?success=${encodeURIComponent("Remark saved successfully!")}`);
});

app.get("/student/:matNumber/info", authenticateToken, fetchUserJWT, fetchUnreadNotifications, reminderMiddleware, async (req, res) => {
  const matNumber = req.params.matNumber;

  const { data: student, error: studentError } = await supabase.from("students").select("*").eq("mat number", matNumber).single();
  if (studentError || !student) {
    return res.status(404).send("Student not found.");
  }

  res.render("student_info", {
    user: req.dbUser,
    student,
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});

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

app.get("/notifications", authenticateToken, fetchUserJWT, fetchUnreadNotifications, async (req, res) => {
  const supervisorEmail = req.dbUser.Email_Address;

  const { data: notifications, error } = await supabase.from("notifications").select("*").eq("supervisor_email", supervisorEmail).order("created_at", { ascending: false });
  
  if (error) return res.status(500).send("Failed to load notifications."); 
  
  res.render("notifications", {
    user: req.dbUser,
    notifications,  
    hasUnreadNotifications: res.locals.hasUnreadNotifications
  });
});  

app.delete("/notifications/:id", authenticateToken, fetchUserJWT, async (req, res) => {
  const { id } = req.params;
  const supervisorEmail = req.dbUser.Email_Address;

  const { error } = await supabase.from("notifications").delete().eq("id", id).eq("supervisor_email", supervisorEmail);

  if (error) return res.status(500).json({ success: false });
  return res.json({ success: true });
});

app.delete("/notifications", authenticateToken, fetchUserJWT, async (req, res) => {
  const supervisorEmail = req.dbUser.Email_Address;

  const { error } = await supabase.from("notifications").delete().eq("supervisor_email", supervisorEmail);

  if (error) return res.status(500).json({ success: false });
  return res.json({ success: true });
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
  const { email, currentPassword, newPassword, confirmPassword } = req.body;

  const { data: user, error } = await supabase.from("it_supervisor").select("*").eq("Email_Address", email).single();
  if (error || !user) {
    return res.render("settings", { user: req.dbUser, error: "User not found." });
  }

  const passwordMatch = await bcrypt.compare(currentPassword, user.password);
  if (!passwordMatch) {
    return res.render("settings", { user: req.dbUser, error: "Current password is incorrect." });
  }
  if (newPassword.length < 8) {
    return res.render("settings", { user: req.dbUser, error: "New password must be at least 8 characters long." });
  }
  if (!isStrongPassword(newPassword)) {
    return res.render("settings", { user: req.dbUser, error: "Password must contain an uppercase, a lowercase, and a number." });
  }
  if (newPassword !== confirmPassword) {
    return res.render("settings", { user: req.dbUser, error: "New passwords do not match." });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 12);
  const { error: updateError } = await supabase.from("it_supervisor").update({ password: hashedPassword }).eq("Email_Address", email);
  if (updateError) {
    return res.render("settings", { user: req.dbUser, error: "Error updating password." });
  }

  res.render("settings", { user: req.dbUser, success: "Password updated successfully!" });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.redirect("/login");
});

app.get('/submit-supervisor', (req, res) => res.render('supervisorForm', { error: null }));

app.post('/submit-supervisor', async (req, res) => {
  const { name, school, department, faculty, phone_number, email_address } = req.body;

  if (!isValidEmail(email_address)) {
    return res.render('supervisorForm', { error: 'Invalid email format.' });
  }
  if (isDisposableEmail(email_address)) {
    return res.render('supervisorForm', { error: 'Disposable emails are not allowed.' });
  }

  let formattedphone;
  try {
    const phone = parsePhoneNumber(phone_number, 'NG');
    if (!phone.isValid() || phone.country !== 'NG') {
      return res.render('supervisorForm', { error: 'Invalid phone number. Must be a valid Nigerian number.' });
    }
    formattedphone = phone.number;
  } catch {
    return res.render('supervisorForm', { error: 'Invalid phone number.' });
  }

  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const { data: nowData, error: nowError } = await supabase.rpc('get_current_timestamp');
    if (nowError) return handleError(res, 'supervisorForm', 'Could not verify server time.');

    const expires_at = new Date(new Date(nowData).getTime() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await supabase.from('OTPs').upsert([{
      email: email_address,
      otp,
      expires_at: expires_at.toISOString(),
      temp_data: { name, school, department, faculty, phone_number: formattedphone, email_address }
    }]);

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
    handleError(res, 'supervisorForm', 'Failed to send OTP.', 500);
  }
});

app.get('/verify-otp', (req, res) => {
  res.render('verifyotp', { email: req.query.email, error: null });
});

app.post('/verify-otp', async (req, res) => {
  const { email, otp: userOtp } = req.body;

  const { data, error } = await supabase.from('OTPs').select('*').eq('email', email).single();
  if (error || !data) return res.render('verifyOtp', { email, error: 'OTP not found.' });
  if (Date.now() > new Date(data.expires_at)) return res.render('verifyOtp', { email, error: 'OTP expired.' });
  if (data.otp !== userOtp) return res.render('verifyOtp', { email, error: 'Incorrect OTP.' });
  res.redirect(`/create-password?email=${encodeURIComponent(email)}`);
});

app.get('/create-password', (req, res) => {
  res.render('createPassword', { email: req.query.email, error: null });
});

app.post('/create-password', async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render('createPassword', { email, error: 'Passwords do not match.' });
  }
  if (!isStrongPassword(password)) {
    return res.render('createPassword', { email, error: 'Password must contain an uppercase letter, a lowercase letter, and a number (min 8 chars).' });
  }

  const { data, error } = await supabase.from('OTPs').select('*').eq('email', email).single();
  if (error || !data || !data.temp_data) {
    return res.render('createPassword', { email, error: 'No temporary data found.' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const temp = data.temp_data;

  const insertResult = await supabase.from('it_supervisor').insert([{
    Name: temp.name,
    School: temp.school,
    Department: temp.department,
    Faculty: temp.faculty,
    "Phone_Number": temp.phone_number,
    "Email_Address": temp.email_address,
    password: hashedPassword,
  }]);
  if (insertResult.error) {
    return res.render('createPassword', { email, error: 'Failed to save form.' });
  }

  await supabase.from('OTPs').delete().eq('email', email);
  res.redirect('/login');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
import { Pool } from "pg";
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { createRealtime, rawSql } from "@neon/realtime/server";

const ORIGIN = process.env.APP_ORIGIN || "https://baraagpt6-droid.github.io";
const JWT_SECRET = process.env.SCHOOL_JWT_SECRET;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 4,
  idleTimeoutMillis: 20000,
  connectionTimeoutMillis: 12000,
  ssl: { rejectUnauthorized: false }
});
pool.on("error", (error) => console.error("Neon pool error", error.message));

const realtime = process.env.NEON_REALTIME_SECRET
  ? createRealtime({ secret: process.env.NEON_REALTIME_SECRET, db: "neondb" })
  : null;

function headers(request) {
  const origin = request.headers.get("origin");
  const allow = !origin || origin === ORIGIN || origin === "null" ? (origin || ORIGIN) : ORIGIN;
  return {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": allow,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "vary": "Origin",
    "x-content-type-options": "nosniff"
  };
}
function send(request, body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: headers(request) });
}
function httpError(message, status = 400, code = "") {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}
async function readBody(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 1024 * 1024) throw httpError("حجم الطلب أكبر من الحد المسموح.", 413);
  try { return await request.json(); }
  catch { throw httpError("صيغة الطلب غير صحيحة.", 400); }
}
function signToken(account) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "alnoor-school-v2",
    sub: account.id,
    role: account.role,
    login_id: account.login_id,
    student_id: account.student_id || null,
    grade: account.grade || null,
    must_change_password: Boolean(account.must_change_password),
    iat: now,
    exp: now + 12 * 60 * 60
  };
  const head = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", JWT_SECRET).update(head + "." + body).digest("base64url");
  return head + "." + body + "." + signature;
}
function decodeToken(request) {
  const token = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const parts = token.split(".");
  if (parts.length !== 3 || !JWT_SECRET) throw httpError("يجب تسجيل الدخول.", 401);
  const input = parts[0] + "." + parts[1];
  const expected = createHmac("sha256", JWT_SECRET).update(input).digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw httpError("جلسة الدخول غير صالحة.", 401);
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")); }
  catch { throw httpError("جلسة الدخول غير صالحة.", 401); }
  if (payload.iss !== "alnoor-school-v2" || !payload.exp || payload.exp < Date.now() / 1000) throw httpError("انتهت جلسة الدخول.", 401);
  return payload;
}
async function requireAccount(request, allowPasswordChange = false) {
  const payload = decodeToken(request);
  const result = await pool.query(
    "SELECT id,login_id,role,display_name,student_id,grade,must_change_password,is_active FROM public.school_accounts WHERE id=$1",
    [payload.sub]
  );
  const account = result.rows[0];
  if (!account || !account.is_active || account.role !== payload.role) throw httpError("الحساب غير نشط أو تغيرت صلاحياته.", 401);
  if (account.must_change_password && !allowPasswordChange) throw httpError("يجب تغيير كلمة المرور المؤقتة أولاً.", 403, "PASSWORD_CHANGE_REQUIRED");
  return account;
}
function requireRole(account, roles) {
  if (!roles.includes(account.role)) throw httpError("ليس لديك صلاحية لتنفيذ هذا الإجراء.", 403);
}
const asArray = (value) => Array.isArray(value) ? value : [];
const idText = (value) => String(value ?? "").trim().slice(0, 120);
const parseJson = (value, fallback) => value == null ? fallback : (typeof value === "string" ? (() => { try { return JSON.parse(value); } catch { return fallback; } })() : value);
const emptySnapshot = () => ({
  students: [], lessons: [], assignments: [], announcements: [],
  parentMessages: [], scheduleByGrade: {}, attendanceRecords: []
});

async function login(request, body) {
  const loginId = idText(body.login_id).toUpperCase();
  const role = String(body.role || "");
  const password = String(body.password || "");
  if (!loginId || !password || !["admin", "teacher", "student", "parent"].includes(role)) throw httpError("أدخل المعرّف وكلمة المرور وحدد البوابة.", 400);
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const key = (await import("node:crypto")).createHash("sha256").update(role + "|" + loginId + "|" + ip).digest("hex");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM public.login_attempts WHERE created_at < now() - interval '1 day'");
    const count = await client.query("SELECT count(*)::int AS n FROM public.login_attempts WHERE attempt_key=$1 AND created_at > now() - interval '15 minutes'", [key]);
    if (count.rows[0].n >= 10) {
      await client.query("COMMIT");
      throw httpError("محاولات الدخول كثيرة. انتظر 15 دقيقة ثم حاول مرة أخرى.", 429);
    }
    await client.query("INSERT INTO public.login_attempts(attempt_key) VALUES($1)", [key]);
    const result = await client.query(
      "SELECT id,login_id,role,display_name,student_id,grade,must_change_password,is_active FROM public.school_accounts WHERE login_id=$1 AND role=$2 AND is_active=true AND password_hash=crypt($3,password_hash) LIMIT 1",
      [loginId, role, password]
    );
    if (!result.rowCount) {
      await client.query("COMMIT");
      throw httpError("رقم القيد أو كلمة المرور غير صحيحة.", 401);
    }
    await client.query("DELETE FROM public.login_attempts WHERE attempt_key=$1", [key]);
    await client.query(
      "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,entity_id) VALUES($1,$2,'login','school_accounts',$1::text)",
      [result.rows[0].id, role]
    );
    await client.query("COMMIT");
    const account = result.rows[0];
    return {
      token: signToken(account),
      user: {
        id: account.id, login_id: account.login_id, role: account.role,
        display_name: account.display_name, student_id: account.student_id,
        grade: account.grade, must_change_password: account.must_change_password
      },
      must_change_password: account.must_change_password
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function changePassword(account, body) {
  const current = String(body.current_password || "");
  const next = String(body.new_password || "");
  if (next.length < 12 || next.length > 128) throw httpError("كلمة المرور الجديدة يجب أن تكون بين 12 و128 خانة.", 400);
  if (current === next) throw httpError("اختر كلمة مرور مختلفة عن المؤقتة.", 400);
  const result = await pool.query(
    "UPDATE public.school_accounts SET password_salt='bcrypt',password_hash=crypt($3,gen_salt('bf',12)),must_change_password=false,updated_at=now() WHERE id=$1 AND password_hash=crypt($2,password_hash) RETURNING id,login_id,role,display_name,student_id,grade,must_change_password",
    [account.id, current, next]
  );
  if (!result.rowCount) throw httpError("كلمة المرور الحالية غير صحيحة.", 401);
  await pool.query(
    "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,entity_id) VALUES($1,$2,'change_password','school_accounts',$1::text)",
    [account.id, account.role]
  );
  return { ok: true, user: result.rows[0] };
}

async function pullSnapshot(account) {
  const studentId = account.student_id || "";
  const grade = account.grade || "";
  if ((account.role === "student" || account.role === "parent") && !studentId) return emptySnapshot();
  let studentRows;
  if (account.role === "admin") {
    studentRows = (await pool.query("SELECT * FROM public.students ORDER BY grade,full_name")).rows;
  } else if (account.role === "teacher") {
    studentRows = (await pool.query("SELECT * FROM public.students WHERE grade=$1 ORDER BY full_name", [grade])).rows;
  } else {
    studentRows = (await pool.query("SELECT * FROM public.students WHERE id=$1", [studentId])).rows;
  }
  const allowedGrades = account.role === "admin" ? null : [...new Set(studentRows.map((row) => row.grade))];
  const students = studentRows.map((s) => ({
    id: s.id, name: s.full_name, grade: s.grade, section: s.section,
    points: s.points, parentName: s.parent_name, parentPhone: s.parent_phone,
    attendance: Number(s.attendance_pct || 0), teacherNote: s.teacher_note,
    marks: parseJson(s.marks, [])
  }));
  let lessonRows = [];
  let assignmentRows = [];
  let announcementRows = [];
  let timetableRows = [];
  let attendanceRows = [];
  let messageRows = [];
  const gradeList = allowedGrades || [];
  if (account.role === "admin") {
    lessonRows = (await pool.query("SELECT * FROM public.lessons ORDER BY grade,subject,title")).rows;
    assignmentRows = (await pool.query("SELECT * FROM public.assignments ORDER BY updated_at DESC")).rows;
    announcementRows = (await pool.query("SELECT * FROM public.announcements ORDER BY published_at DESC")).rows;
    timetableRows = (await pool.query("SELECT * FROM public.timetable ORDER BY grade,weekday,period")).rows;
    attendanceRows = (await pool.query("SELECT a.*,s.grade FROM public.attendance a JOIN public.students s ON s.id=a.student_id ORDER BY event_date DESC")).rows;
    messageRows = (await pool.query("SELECT * FROM public.messages ORDER BY created_at DESC LIMIT 500")).rows;
  } else if (account.role === "teacher") {
    lessonRows = (await pool.query("SELECT * FROM public.lessons WHERE grade IS NULL OR grade=$1 ORDER BY subject,title", [grade])).rows;
    assignmentRows = (await pool.query("SELECT * FROM public.assignments WHERE grade IS NULL OR grade=$1 ORDER BY updated_at DESC", [grade])).rows;
    announcementRows = (await pool.query("SELECT * FROM public.announcements WHERE target_grade IS NULL OR target_grade=$1 ORDER BY published_at DESC", [grade])).rows;
    timetableRows = (await pool.query("SELECT * FROM public.timetable WHERE grade=$1 ORDER BY weekday,period", [grade])).rows;
    attendanceRows = (await pool.query("SELECT a.*,s.grade FROM public.attendance a JOIN public.students s ON s.id=a.student_id WHERE s.grade=$1 ORDER BY event_date DESC", [grade])).rows;
    messageRows = (await pool.query("SELECT m.* FROM public.messages m LEFT JOIN public.students s ON s.id=m.student_id WHERE s.grade=$1 ORDER BY m.created_at DESC LIMIT 500", [grade])).rows;
  } else {
    const student = studentRows[0];
    const g = student?.grade || "";
    lessonRows = (await pool.query("SELECT * FROM public.lessons WHERE grade IS NULL OR grade=$1 ORDER BY subject,title", [g])).rows;
    assignmentRows = (await pool.query("SELECT * FROM public.assignments WHERE grade IS NULL OR grade=$1 ORDER BY updated_at DESC", [g])).rows;
    announcementRows = (await pool.query("SELECT * FROM public.announcements WHERE target_grade IS NULL OR target_grade=$1 ORDER BY published_at DESC", [g])).rows;
    timetableRows = (await pool.query("SELECT * FROM public.timetable WHERE grade=$1 ORDER BY weekday,period", [g])).rows;
    attendanceRows = (await pool.query("SELECT a.*,s.grade FROM public.attendance a JOIN public.students s ON s.id=a.student_id WHERE a.student_id=$1 ORDER BY event_date DESC", [studentId])).rows;
    messageRows = (await pool.query("SELECT * FROM public.messages WHERE student_id=$1 ORDER BY created_at DESC LIMIT 200", [studentId])).rows;
  }
  const lessons = lessonRows.map((row) => ({
    ...parseJson(row.payload, {}),
    id: row.id, grade: row.grade, subject: row.subject, title: row.title
  }));
  const assignments = assignmentRows.map((row) => ({
    id: row.id, title: row.title, details: row.details, question: row.question,
    grade: row.grade, section: row.section, dueDate: row.due_at,
    subject: row.details?.subject || "", options: parseJson(row.options, []),
    correctIndex: row.correct_index, xp: row.xp,
    submissions: parseJson(row.submissions, {})
  }));
  const announcements = announcementRows.map((row) => ({
    id: row.id, title: row.title, date: row.published_at,
    body: row.details, targetGrade: row.target_grade
  }));
  const attendanceMap = new Map();
  for (const row of attendanceRows) {
    const key = row.grade + "|" + String(row.event_date).slice(0, 10);
    if (!attendanceMap.has(key)) attendanceMap.set(key, {
      id: row.grade + "-" + String(row.event_date).slice(0, 10),
      grade: row.grade, date: String(row.event_date).slice(0, 10), entries: {}
    });
    attendanceMap.get(key).entries[row.student_id] = row.status;
  }
  const scheduleByGrade = {};
  for (const row of timetableRows) {
    if (!scheduleByGrade[row.grade]) scheduleByGrade[row.grade] = [];
    const list = scheduleByGrade[row.grade];
    let day = list.find((item) => item.day === row.weekday);
    if (!day) { day = { day: row.weekday, classes: "" }; list.push(day); }
    day.classes = day.classes ? day.classes + " • " + row.subject : row.subject;
  }
  const parentMessages = messageRows.map((row) => ({
    id: row.id, studentId: row.student_id, from: row.sender_name,
    text: row.body, time: row.created_at, reply: row.reply || "",
    replyTime: row.reply_time || ""
  }));
  return {
    students, lessons, assignments, announcements, parentMessages,
    scheduleByGrade, attendanceRecords: [...attendanceMap.values()]
  };
}

async function saveMarks(client, studentId, marks, actorId) {
  for (const mark of asArray(marks)) {
    if (!mark || !mark.subject) continue;
    const term = String(mark.term || "الفصل الأول").slice(0, 80);
    const termWork = Math.max(0, Math.min(40, Number(mark.termWork) || 0));
    const finalExam = Math.max(0, Math.min(60, Number(mark.finalExam) || 0));
    await client.query(
      "INSERT INTO public.grades(id,student_id,subject,term,term_work,final_exam,teacher_note,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(student_id,subject,term) DO UPDATE SET term_work=EXCLUDED.term_work,final_exam=EXCLUDED.final_exam,teacher_note=EXCLUDED.teacher_note,updated_at=now(),updated_by=EXCLUDED.updated_by",
      [studentId + "-" + mark.subject + "-" + term, studentId, String(mark.subject).slice(0,100), term, termWork, finalExam, mark.teacherNote || null, actorId]
    );
  }
}

async function syncPush(account, body) {
  const changes = body.changes && typeof body.changes === "object" ? body.changes : {};
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (["admin","teacher"].includes(account.role) && Array.isArray(changes.students)) {
      for (const student of changes.students) {
        if (!student || !student.id || !student.name || !student.grade) continue;
        if (account.role === "teacher") {
          if (student.grade !== account.grade) continue;
          await client.query(
            "UPDATE public.students SET marks=$2::jsonb,teacher_note=$3,updated_at=now(),updated_by=$4 WHERE id=$1 AND grade=$5",
            [String(student.id), JSON.stringify(asArray(student.marks)), student.teacherNote || null, account.id, account.grade]
          );
          await saveMarks(client, String(student.id), student.marks, account.id);
        } else {
          await client.query(
            "INSERT INTO public.students(id,admission_no,full_name,grade,section,points,parent_name,parent_phone,attendance_pct,teacher_note,marks,updated_by) VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11) ON CONFLICT(id) DO UPDATE SET admission_no=EXCLUDED.admission_no,full_name=EXCLUDED.full_name,grade=EXCLUDED.grade,section=EXCLUDED.section,points=EXCLUDED.points,parent_name=EXCLUDED.parent_name,parent_phone=EXCLUDED.parent_phone,attendance_pct=EXCLUDED.attendance_pct,teacher_note=EXCLUDED.teacher_note,marks=EXCLUDED.marks,updated_at=now(),updated_by=EXCLUDED.updated_by",
            [String(student.id), String(student.name).slice(0,160), String(student.grade), String(student.section || "أ"), Math.max(0,Number(student.points)||0), student.parentName || null, student.parentPhone || null, Math.max(0,Math.min(100,Number(student.attendance)||0)), student.teacherNote || null, JSON.stringify(asArray(student.marks)), account.id]
          );
          await saveMarks(client, String(student.id), student.marks, account.id);
        }
      }
    }

    if (["admin","teacher"].includes(account.role) && Array.isArray(changes.lessons)) {
      for (const lesson of changes.lessons) {
        if (!lesson?.id || !lesson?.title) continue;
        if (account.role === "teacher" && lesson.grade && lesson.grade !== account.grade) continue;
        await client.query(
          "INSERT INTO public.lessons(id,grade,subject,title,payload,updated_by) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(id) DO UPDATE SET grade=EXCLUDED.grade,subject=EXCLUDED.subject,title=EXCLUDED.title,payload=EXCLUDED.payload,updated_at=now(),updated_by=EXCLUDED.updated_by",
          [String(lesson.id), lesson.grade || null, lesson.subject || null, String(lesson.title).slice(0,200), JSON.stringify(lesson), account.id]
        );
      }
    }

    if (["admin","teacher"].includes(account.role) && Array.isArray(changes.assignments)) {
      for (const item of changes.assignments) {
        if (!item?.id || !item?.title) continue;
        if (account.role === "teacher" && item.grade && item.grade !== account.grade) continue;
        await client.query(
          "INSERT INTO public.assignments(id,title,details,question,grade,section,due_at,options,correct_index,xp,submissions,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::jsonb,$12) ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,details=EXCLUDED.details,question=EXCLUDED.question,grade=EXCLUDED.grade,section=EXCLUDED.section,due_at=EXCLUDED.due_at,options=EXCLUDED.options,correct_index=EXCLUDED.correct_index,xp=EXCLUDED.xp,submissions=EXCLUDED.submissions,updated_at=now()",
          [String(item.id), String(item.title).slice(0,200), item.details || item.subject || null, item.question || null, item.grade || (account.role === "teacher" ? account.grade : null), item.section || null, item.dueDate || null, JSON.stringify(asArray(item.options)), Number.isInteger(Number(item.correctIndex)) ? Number(item.correctIndex) : null, Math.max(0,Math.min(100,Number(item.xp)||0)), JSON.stringify(item.submissions || {}), account.id]
        );
      }
    }

    if (account.role === "admin" && Array.isArray(changes.announcements)) {
      for (const item of changes.announcements) {
        if (!item?.id || !item?.title) continue;
        await client.query(
          "INSERT INTO public.announcements(id,title,details,target_grade,published_at,created_by) VALUES($1,$2,$3,$4,COALESCE($5::timestamptz,now()),$6) ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,details=EXCLUDED.details,target_grade=EXCLUDED.target_grade,updated_at=now()",
          [String(item.id), String(item.title).slice(0,200), item.body || item.details || "", item.targetGrade || null, item.date && !Number.isNaN(Date.parse(item.date)) ? new Date(item.date).toISOString() : null, account.id]
        );
      }
    }

    if (["admin","teacher"].includes(account.role) && Array.isArray(changes.attendanceRecords)) {
      for (const record of changes.attendanceRecords) {
        if (!record?.grade || !record?.date || !record.entries) continue;
        if (account.role === "teacher" && record.grade !== account.grade) continue;
        for (const [studentId, status] of Object.entries(record.entries)) {
          if (!["present","absent","late"].includes(status)) continue;
          const studentExists = await client.query("SELECT id FROM public.students WHERE id=$1 AND grade=$2", [studentId, record.grade]);
          if (!studentExists.rowCount) continue;
          await client.query(
            "INSERT INTO public.attendance(id,student_id,event_date,status,updated_by) VALUES($1,$2,$3::date,$4,$5) ON CONFLICT(student_id,event_date) DO UPDATE SET status=EXCLUDED.status,updated_at=now(),updated_by=EXCLUDED.updated_by",
            [record.id + "-" + studentId, studentId, record.date, status, account.id]
          );
        }
      }
    }

    if (["admin","teacher"].includes(account.role) && changes.scheduleByGrade && typeof changes.scheduleByGrade === "object") {
      for (const [scheduleGrade, rows] of Object.entries(changes.scheduleByGrade)) {
        if (account.role === "teacher" && scheduleGrade !== account.grade) continue;
        for (const row of asArray(rows)) {
          if (!row?.day) continue;
          await client.query(
            "INSERT INTO public.timetable(id,grade,weekday,period,subject,updated_at) VALUES($1,$2,$3,1,$4,now()) ON CONFLICT(grade,section,weekday,period) DO UPDATE SET subject=EXCLUDED.subject,updated_at=now()",
            [scheduleGrade + "-" + row.day, scheduleGrade, row.day, String(row.classes || "").slice(0,600)]
          );
        }
      }
    }

    if (Array.isArray(changes.parentMessages)) {
      if (account.role === "parent") {
        if (!account.student_id) throw httpError("حساب ولي الأمر غير مرتبط بطالب.", 403);
        for (const message of changes.parentMessages) {
          if (!message?.id || !String(message.text || "").trim()) continue;
          await client.query(
            "INSERT INTO public.messages(id,student_id,sender_user_id,sender_role,sender_name,body) VALUES($1,$2,$3,'parent',$4,$5) ON CONFLICT(id) DO NOTHING",
            [String(message.id), account.student_id, account.id, account.display_name, String(message.text).slice(0,1200)]
          );
        }
      } else if (["admin","teacher"].includes(account.role)) {
        for (const message of changes.parentMessages) {
          if (!message?.id || !message.reply) continue;
          const permitted = account.role === "admin" ? "" : account.grade;
          await client.query(
            "UPDATE public.messages m SET reply=$2,replied_by=$3,reply_time=now(),updated_at=now() FROM public.students s WHERE m.id=$1 AND s.id=m.student_id AND ($4='' OR s.grade=$4)",
            [String(message.id), String(message.reply).slice(0,1200), account.id, permitted]
          );
        }
      }
    }
    await client.query(
      "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,metadata) VALUES($1,$2,'sync_push','school_data',$3::jsonb)",
      [account.id, account.role, JSON.stringify({ keys: Object.keys(changes) })]
    );
    await client.query("COMMIT");
    return { ok: true, synchronized: Object.keys(changes) };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function createSchoolAccount(actor, body) {
  requireRole(actor, ["admin"]);
  const role = String(body.role || "");
  const loginId = idText(body.login_id).toUpperCase();
  const displayName = String(body.display_name || "").trim().slice(0,160);
  const studentId = body.student_id ? String(body.student_id) : null;
  const grade = body.grade ? String(body.grade) : null;
  if (!["teacher","student","parent","admin"].includes(role) || !loginId || !displayName) throw httpError("تحقق من بيانات الحساب.", 400);
  if (["student","parent"].includes(role)) {
    const found = await pool.query("SELECT id,grade FROM public.students WHERE id=$1", [studentId]);
    if (!found.rowCount) throw httpError("رقم الطالب المرتبط غير موجود.", 400);
  }
  if (role === "teacher" && !grade) throw httpError("اختر الصف المكلف به المعلم.", 400);
  const password = randomBytes(16).toString("base64url");
  const result = await pool.query(
    "INSERT INTO public.school_accounts(login_id,role,display_name,student_id,grade,password_salt,password_hash,must_change_password) VALUES($1,$2,$3,$4,$5,'bcrypt',crypt($6,gen_salt('bf',12)),true) RETURNING id,login_id,role,display_name,student_id,grade",
    [loginId, role, displayName, studentId, grade, password]
  );
  await pool.query(
    "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,entity_id) VALUES($1,'admin','create_account','school_accounts',$2)",
    [actor.id, result.rows[0].id]
  );
  return { account: result.rows[0], password };
}

async function seedDefaults(actor, body) {
  requireRole(actor, ["admin"]);
  const data = body.data;
  if (!data || !Array.isArray(data.students) || !Array.isArray(data.lessons)) throw httpError("بيانات التهيئة الافتراضية غير مكتملة.", 400);
  const already = await pool.query("SELECT value FROM public.school_settings WHERE key='seeded_at'");
  if (already.rowCount) throw httpError("تمت تهيئة المدرسة سابقاً.", 409);
  const client = await pool.connect();
  const issued = [];
  try {
    await client.query("BEGIN");
    const studentIds = [];
    for (const s of data.students) {
      if (!s?.id || !s?.name || !s?.grade) continue;
      studentIds.push(String(s.id));
      await client.query(
        "INSERT INTO public.students(id,admission_no,full_name,grade,section,points,parent_name,parent_phone,attendance_pct,teacher_note,marks) VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) ON CONFLICT(id) DO NOTHING",
        [String(s.id), String(s.name), String(s.grade), s.section || "أ", Number(s.points)||0, s.parentName || null, s.parentPhone || null, Number(s.attendance)||0, s.teacherNote || null, JSON.stringify(asArray(s.marks))]
      );
      for (const mark of asArray(s.marks)) {
        await saveMarks(client, String(s.id), [mark], actor.id);
      }
    }
    for (const lesson of data.lessons) {
      if (!lesson?.id || !lesson?.title) continue;
      await client.query(
        "INSERT INTO public.lessons(id,grade,subject,title,payload,updated_by) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(id) DO NOTHING",
        [String(lesson.id), lesson.grade || null, lesson.subject || null, String(lesson.title), JSON.stringify(lesson), actor.id]
      );
    }
    for (const a of asArray(data.assignments)) {
      if (!a?.id || !a?.title) continue;
      await client.query(
        "INSERT INTO public.assignments(id,title,details,question,grade,options,correct_index,xp,submissions,created_by) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9::jsonb,$10) ON CONFLICT(id) DO NOTHING",
        [String(a.id), String(a.title), a.subject || null, a.question || null, a.grade || null, JSON.stringify(asArray(a.options)), Number(a.correctIndex)||0, Number(a.xp)||0, JSON.stringify(a.submissions||{}), actor.id]
      );
    }
    for (const a of asArray(data.announcements)) {
      if (!a?.id || !a?.title) continue;
      await client.query(
        "INSERT INTO public.announcements(id,title,details,target_grade,published_at,created_by) VALUES($1,$2,$3,$4,now(),$5) ON CONFLICT(id) DO NOTHING",
        [String(a.id), String(a.title), a.body || "", a.targetGrade || null, actor.id]
      );
    }
    for (const [grade, rows] of Object.entries(data.scheduleByGrade || {})) {
      for (const row of asArray(rows)) {
        if (!row?.day) continue;
        await client.query(
          "INSERT INTO public.timetable(id,grade,weekday,period,subject) VALUES($1,$2,$3,1,$4) ON CONFLICT(grade,section,weekday,period) DO NOTHING",
          [grade + "-" + row.day, grade, row.day, String(row.classes || "")]
        );
      }
    }
    const makeAccount = async (loginId, role, displayName, studentId, grade) => {
      const password = randomBytes(16).toString("base64url");
      const result = await client.query(
        "INSERT INTO public.school_accounts(login_id,role,display_name,student_id,grade,password_salt,password_hash,must_change_password) VALUES($1,$2,$3,$4,$5,'bcrypt',crypt($6,gen_salt('bf',12)),true) ON CONFLICT(role,login_id) DO NOTHING RETURNING id",
        [loginId, role, displayName, studentId, grade, password]
      );
      if (result.rowCount) issued.push({ login_id: loginId, role, display_name: displayName, password });
    };
    for (const s of data.students) {
      if (!s?.id) continue;
      await makeAccount(String(s.id), "student", s.name, String(s.id), s.grade);
      await makeAccount(String(s.id), "parent", "ولي أمر " + s.name, String(s.id), s.grade);
    }
    const teacherGrade = data.students[0]?.grade || null;
    if (teacherGrade) await makeAccount("TCH-01", "teacher", "معلم تجريبي", null, teacherGrade);
    await client.query("INSERT INTO public.school_settings(key,value) VALUES('seeded_at',to_jsonb(now()::text)) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()");
    await client.query(
      "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,metadata) VALUES($1,'admin','seed_defaults','school_data',$2::jsonb)",
      [actor.id, JSON.stringify({ students: studentIds.length, lessons: data.lessons.length, accounts: issued.length })]
    );
    await client.query("COMMIT");
    return { ok: true, issued_accounts: issued };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function syncStudentProgress(account, body) {
  requireRole(account, ["student"]);
  if (!account.student_id) throw httpError("حساب الطالب غير مرتبط بسجل طالب.", 403);
  const completed = [...new Set(asArray(body.completed_lessons).map(String))].slice(0,500);
  const quizzes = asArray(body.quiz_submissions).slice(0,1000);
  const submissions = body.assignment_submissions && typeof body.assignment_submissions === "object" && !Array.isArray(body.assignment_submissions) ? body.assignment_submissions : {};
  const client = await pool.connect();
  let earned = 0;
  try {
    await client.query("BEGIN");
    const studentResult = await client.query("SELECT id,grade,points FROM public.students WHERE id=$1 FOR UPDATE", [account.student_id]);
    if (!studentResult.rowCount) throw httpError("سجل الطالب غير موجود.", 404);
    const student = studentResult.rows[0];
    const existingProgress = await client.query("SELECT completed_lessons,quiz_completed_by FROM public.student_progress WHERE student_id=$1 FOR UPDATE", [account.student_id]);
    const previous = existingProgress.rows[0] || { completed_lessons: [], quiz_completed_by: [] };
    const completedSet = new Set(asArray(previous.completed_lessons));
    const quizSet = new Set(asArray(previous.quiz_completed_by));

    for (const lessonId of completed) {
      if (completedSet.has(lessonId)) continue;
      const found = await client.query("SELECT id,payload FROM public.lessons WHERE id=$1 AND (grade IS NULL OR grade=$2) FOR UPDATE", [lessonId, student.grade]);
      if (!found.rowCount) continue;
      const payload = found.rows[0].payload || {};
      const done = [...new Set([...asArray(payload.completedBy), account.student_id])];
      payload.completedBy = done;
      await client.query("UPDATE public.lessons SET payload=$2::jsonb,updated_at=now() WHERE id=$1", [lessonId, JSON.stringify(payload)]);
      completedSet.add(lessonId);
      earned += Math.max(0, Math.min(100, Number(payload.xp) || 0));
    }

    for (const item of quizzes) {
      const lessonId = String(item.lesson_id || "");
      const quizId = String(item.quiz_id || "");
      const answer = Number(item.answer);
      if (!lessonId || !quizId || !Number.isInteger(answer)) continue;
      const found = await client.query("SELECT id,payload FROM public.lessons WHERE id=$1 AND (grade IS NULL OR grade=$2) FOR UPDATE", [lessonId, student.grade]);
      if (!found.rowCount) continue;
      const payload = found.rows[0].payload || {};
      const quiz = asArray(payload.questions).find((q) => String(q.id) === quizId);
      if (!quiz || Number(quiz.correctIndex) !== answer) continue;
      const key = account.student_id + ":" + lessonId + ":" + quizId;
      if (quizSet.has(key)) continue;
      quizSet.add(key);
      payload.quizCompletedBy = [...new Set([...asArray(payload.quizCompletedBy), key])];
      payload.quizSubmissions = { ...(payload.quizSubmissions || {}), [key]: { answer: answer, verified: true } };
      await client.query("UPDATE public.lessons SET payload=$2::jsonb,updated_at=now() WHERE id=$1", [lessonId, JSON.stringify(payload)]);
      earned += Math.max(0, Math.min(100, Number(quiz.xp) || 10));
    }

    for (const [assignmentId, submission] of Object.entries(submissions).slice(0,300)) {
      if (!submission || typeof submission !== "object") continue;
      const found = await client.query("SELECT id,grade,correct_index,xp,submissions FROM public.assignments WHERE id=$1 AND (grade IS NULL OR grade=$2) FOR UPDATE", [String(assignmentId), student.grade]);
      if (!found.rowCount) continue;
      const row = found.rows[0];
      const option = Number(submission.optionIdx);
      const correct = Number.isInteger(option) && option === Number(row.correct_index);
      const old = row.submissions && typeof row.submissions === "object" ? row.submissions : {};
      const previousSubmission = old[account.student_id];
      const reward = correct && !(previousSubmission?.isCorrect || previousSubmission?.rewarded);
      old[account.student_id] = { optionIdx: Number.isInteger(option) ? option : null, isCorrect: correct, rewarded: Boolean(previousSubmission?.rewarded || reward) };
      await client.query("UPDATE public.assignments SET submissions=$2::jsonb,updated_at=now() WHERE id=$1", [row.id, JSON.stringify(old)]);
      if (reward) earned += Math.max(0, Math.min(100, Number(row.xp) || 0));
    }

    await client.query(
      "INSERT INTO public.student_progress(student_id,completed_lessons,quiz_completed_by) VALUES($1,$2::jsonb,$3::jsonb) ON CONFLICT(student_id) DO UPDATE SET completed_lessons=EXCLUDED.completed_lessons,quiz_completed_by=EXCLUDED.quiz_completed_by,updated_at=now()",
      [account.student_id, JSON.stringify([...completedSet]), JSON.stringify([...quizSet])]
    );
    if (earned) await client.query("UPDATE public.students SET points=points+$2,updated_at=now() WHERE id=$1", [account.student_id, earned]);
    await client.query(
      "INSERT INTO public.audit_log(actor_id,actor_role,action,entity,entity_id,metadata) VALUES($1,'student','sync_progress','student_progress',$2,$3::jsonb)",
      [account.id, account.student_id, JSON.stringify({ lessons: completedSet.size, quizzes: quizSet.size, earned })]
    );
    await client.query("COMMIT");
    return { ok: true, completed_lessons: completedSet.size, quiz_completions: quizSet.size, earned_points: earned, points: Number(student.points || 0) + earned };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function assistant(account, body) {
  const question = String(body.question || "").trim().slice(0,1000);
  if (!question) throw httpError("اكتب سؤالك أولاً.", 400);
  const recent = await pool.query("SELECT count(*)::int AS n FROM public.assistant_usage WHERE account_id=$1 AND created_at > now() - interval '1 minute'", [account.id]);
  if (recent.rows[0].n >= 12) throw httpError("وصلت إلى حد الأسئلة المؤقت. حاول بعد دقيقة.", 429);
  await pool.query("INSERT INTO public.assistant_usage(account_id) VALUES($1)", [account.id]);
  const system = [
    "أنت مساعد نور التعليمي لمدرسة يمنية. أجب بالعربية الواضحة.",
    "ساعد في المنهج اليمني والعلوم العامة. اشرح الرياضيات خطوة بخطوة والنحو مع أمثلة.",
    "لا تخترع نصوص الكتب أو أرقام الصفحات. ميّز بين المعلومات المؤكدة والتخمين.",
    "دور السائل: " + account.role + ". الصف: " + (account.grade || "غير محدد") + "."
  ].join("\n");
  if (process.env.GEMINI_API_KEY) {
    const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";
    const url = "https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(model) + ":generateContent?key=" + encodeURIComponent(process.env.GEMINI_API_KEY);
    const response = await fetch(url, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents: [{ role: "user", parts: [{ text: question }] }], generationConfig: { temperature: 0.4, maxOutputTokens: 1200 } })
    });
    const payload = await response.json().catch(() => ({}));
    const reply = payload?.candidates?.[0]?.content?.parts?.map((x) => x.text || "").join("").trim();
    if (response.ok && reply) return { reply, provider: "gemini" };
    throw httpError("خدمة المساعد غير متاحة حالياً.", 503);
  }
  if (process.env.GROQ_API_KEY) {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + process.env.GROQ_API_KEY },
      body: JSON.stringify({ model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile", messages: [{ role: "system", content: system }, { role: "user", content: question }], temperature: 0.4, max_tokens: 1200 })
    });
    const payload = await response.json().catch(() => ({}));
    const reply = payload?.choices?.[0]?.message?.content?.trim();
    if (response.ok && reply) return { reply, provider: "groq" };
    throw httpError("خدمة المساعد غير متاحة حالياً.", 503);
  }
  const response = await fetch("https://text.pollinations.ai/openai", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ model: process.env.AI_MODEL || "openai-fast", messages: [{ role: "system", content: system }, { role: "user", content: question }], temperature: 0.4, max_tokens: 1100 })
  });
  const payload = await response.json().catch(() => ({}));
  const reply = payload?.choices?.[0]?.message?.content || payload.reply || payload.answer || payload.text;
  if (!response.ok || typeof reply !== "string" || !reply.trim()) throw httpError("خدمة المساعد الخارجية غير متاحة. سيستخدم التطبيق المحرك المحلي.", 503);
  return { reply: reply.trim().slice(0,9000), provider: "pollinations" };
}

async function sealRealtime(account) {
  if (!realtime) throw httpError("المزامنة الحية غير مهيأة على الخادم.", 503);
  const sealed = await realtime.seal({
    query: rawSql("SELECT id FROM public.sync_events ORDER BY id DESC LIMIT 1")
  });
  return { sealed };
}

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(request) });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (request.method === "GET" && (path === "/" || path === "/health" || path === "/api/health")) {
        const result = await pool.query("SELECT current_database() AS database, now() AS server_time, 1 AS healthy");
        return send(request, { ok: true, service: "alnoor-school-api", version: "2.0.0", database: result.rows[0] });
      }
      if (request.method === "POST" && path === "/api/auth/login") {
        return send(request, await login(request, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/auth/change-password") {
        const account = await requireAccount(request, true);
        return send(request, await changePassword(account, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/auth/logout") {
        await requireAccount(request, true);
        return send(request, { ok: true });
      }
      if (request.method === "GET" && path === "/api/me") {
        const account = await requireAccount(request, true);
        return send(request, { user: account });
      }
      if (request.method === "POST" && path === "/api/sync/pull") {
        const account = await requireAccount(request);
        return send(request, await pullSnapshot(account));
      }
      if (request.method === "POST" && path === "/api/sync/push") {
        const account = await requireAccount(request);
        return send(request, await syncPush(account, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/admin/seed-defaults") {
        const account = await requireAccount(request);
        return send(request, await seedDefaults(account, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/admin/accounts") {
        const account = await requireAccount(request);
        return send(request, { account: (await createSchoolAccount(account, await readBody(request))).account, password: "TEMPORARY_PASSWORD_NOT_AVAILABLE" });
      }
      if (request.method === "POST" && path === "/api/student/progress") {
        const account = await requireAccount(request);
        return send(request, await syncStudentProgress(account, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/assistant") {
        const account = await requireAccount(request);
        return send(request, await assistant(account, await readBody(request)));
      }
      if (request.method === "POST" && path === "/api/realtime/seal") {
        const account = await requireAccount(request);
        return send(request, await sealRealtime(account));
      }
      return send(request, { error: "المسار غير موجود." }, 404);
    } catch (error) {
      console.error("Alnoor API error", path, error.message);
      return send(request, {
        error: error.status && error.status < 500 ? error.message : "تعذر تنفيذ الطلب على خادم المدرسة.",
        code: error.code || "",
        request_id: randomBytes(6).toString("hex")
      }, error.status || 500);
    }
  }
};

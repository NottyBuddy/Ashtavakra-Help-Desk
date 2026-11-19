import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = process.cwd();
const requiredFiles = [
  "index.html", "login.html", "admin.html", "admin-recovery.html",
  "functions/_middleware.js", "functions/api/[[path]].js",
  "migrations/0001_auth.sql", "wrangler.toml"
];
const failures = [];
for (const file of requiredFiles) {
  const full = path.join(root, file);
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) failures.push(`Missing required portal file: ${file}`);
}
function checkInlineScripts(file) {
  const html = fs.readFileSync(path.join(root, file), "utf8");
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  let checked = 0;
  for (const [, attributes, source] of scripts) {
    if (/\bsrc\s*=/.test(attributes) || /\btype\s*=\s*["']module["']/i.test(attributes) || !source.trim()) continue;
    checked += 1;
    try { new vm.Script(source, { filename: `${file} inline script ${checked}` }); }
    catch (error) { failures.push(`JavaScript syntax error in ${file}, inline script ${checked}: ${error.message}`); }
  }
  if (checked === 0) failures.push(`No inline application script found in ${file}`);
}
for (const file of ["index.html", "login.html", "admin.html", "admin-recovery.html"]) {
  if (fs.existsSync(path.join(root, file))) checkInlineScripts(file);
}
const apiPath = path.join(root, "functions/api/[[path]].js");
if (fs.existsSync(apiPath)) {
  const api = fs.readFileSync(apiPath, "utf8");
  for (const endpoint of ["/api/auth/login", "/api/auth/me", "/api/auth/change-password", "/api/auth/logout"]) {
    if (!api.includes(endpoint)) failures.push(`Authentication endpoint missing from API router: ${endpoint}`);
  }
}
if (failures.length) {
  console.error("Portal verification failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("Portal verification passed: required files and inline JavaScript syntax are valid.");

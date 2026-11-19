import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = process.cwd();
const requiredFiles = [
  "index.html", "assets/css/portal.css", "assets/js/portal.js",
  "login.html", "admin.html", "admin-recovery.html",
  "functions/_middleware.js", "functions/api/[[path]].js",
  "migrations/0001_auth.sql", "wrangler.toml"
];
const failures = [];
for (const file of requiredFiles) {
  const full = path.join(root, file);
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) failures.push(`Missing required portal file: ${file}`);
}
function checkHtmlScripts(file) {
  const html = fs.readFileSync(path.join(root, file), "utf8");
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  let checked = 0;
  for (const [, attributes, source] of scripts) {
    const src = attributes.match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1];
    if (src) {
      if (/^https?:\/\//i.test(src) || src.startsWith("//")) continue;
      const local = path.normalize(path.join(path.dirname(file), src));
      if (!fs.existsSync(path.join(root, local))) {
        failures.push(`Missing local script referenced by ${file}: ${src}`);
        continue;
      }
      try { new vm.Script(fs.readFileSync(path.join(root, local), "utf8"), { filename: local }); checked++; }
      catch (error) { failures.push(`JavaScript syntax error in ${local}: ${error.message}`); }
      continue;
    }
    if (/\btype\s*=\s*["']module["']/i.test(attributes) || !source.trim()) continue;
    try { new vm.Script(source, { filename: `${file} inline script` }); checked++; }
    catch (error) { failures.push(`JavaScript syntax error in ${file}: ${error.message}`); }
  }
  if (checked === 0) failures.push(`No local application script found in ${file}`);
}
for (const file of ["index.html", "login.html", "admin.html", "admin-recovery.html"]) {
  if (fs.existsSync(path.join(root, file))) checkHtmlScripts(file);
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
console.log("Portal verification passed: required files, local scripts and JavaScript syntax are valid.");

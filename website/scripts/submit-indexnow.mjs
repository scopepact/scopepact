import { readFile } from "node:fs/promises";

const key = "12d8158837f8502a47a415ef42f21702";
const keyFile = new URL(`../public/${key}.txt`, import.meta.url);
const storedKey = (await readFile(keyFile, "utf8")).trim();

if (storedKey !== key) {
  throw new Error(`IndexNow key file does not match ${key}.txt`);
}

const payload = {
  host: "scopepact.org",
  key,
  keyLocation: `https://scopepact.org/${key}.txt`,
  urlList: [
    "https://scopepact.org/",
    "https://scopepact.org/articles/ai-agents-need-bounded-authority",
  ],
};

const response = await fetch("https://api.indexnow.org/indexnow", {
  method: "POST",
  headers: { "content-type": "application/json; charset=utf-8" },
  body: JSON.stringify(payload),
});

if (response.status !== 200 && response.status !== 202) {
  const body = await response.text();
  throw new Error(`IndexNow returned HTTP ${response.status}: ${body}`);
}

console.log(`IndexNow accepted ${payload.urlList.length} URLs (HTTP ${response.status}).`);

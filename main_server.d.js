#!/usr/bin/env node
/**
 * 1) Reads/writes local `cache.json` for token & userId (prompts if missing)
 * 2) Dynamically fetches "latest measurement" from /llu/connections/{patientId}/graph,
 *    scheduling the next request based on the last reading's exact timestamp + 60s + offset.
 * 3) Stores each "latest measurement" in `latestMeasurements.json` (only today's remain)
 * 4) Exposes an HTTPS server with endpoints:
 *    - /patient-info
 *    - /sensor-info
 *    - /measurement-mgdl
 *    - /measurement-mmol
 *
 *    Now also includes:
 *      - measurementColor: numeric (1..4)
 *      - measurementColorName: mapped string ("green", "yellow", "orange", "red")
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const axios = require('axios');
const express = require('express');
const https = require('https');

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Configuration: SSL certificate & key paths
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
const keyFile = '/home/local/librelinkup-api/private.key';    // <-- Adjust as needed
const certFile = '/home/local/librelinkup-api/certificate.crt'; // <-- Adjust as needed

// Load the SSL credentials
const sslOptions = {
  key: fs.readFileSync(keyFile),
  cert: fs.readFileSync(certFile)
  // If you have an intermediate bundle, you can add: ca: fs.readFileSync('/path/to/chainfile.pem')
};

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// File paths
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
const CACHE_FILE = path.join(__dirname, 'cache.json'); 
const MEASUREMENTS_FILE = path.join(__dirname, 'latestMeasurements.json');

// In-memory data store for serving via Express
const memoryData = {
  patientInfo: null,
  sensorInfo: null,
  measurementMgdl: null,
  measurementMmol: null
};

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Axios client for LibreLinkUp
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
let baseURL = 'https://api.libreview.io';
const apiClient = axios.create({
  baseURL,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'accept-encoding': 'gzip',
    'cache-control': 'no-cache',
    connection: 'Keep-Alive',

    product: 'llu.android',
    version: '4.12',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:129.0) Gecko/20100101 Firefox/129.0'
  }
});

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Readline for prompting
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function askQuestion(query) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Cache for token (cache.json)
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function readCache() {
  if (!fs.existsSync(CACHE_FILE)) return {};
  try {
    const raw = fs.readFileSync(CACHE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.warn('[WARN] Could not parse cache.json:', err.message);
    return {};
  }
}

function writeCache(obj) {
  fs.writeFileSync(CACHE_FILE, JSON.stringify(obj, null, 2), 'utf8');
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Measurements file for daily data (latestMeasurements.json)
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function readMeasurementsFile() {
  if (!fs.existsSync(MEASUREMENTS_FILE)) {
    return [];
  }
  try {
    const raw = fs.readFileSync(MEASUREMENTS_FILE, 'utf8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      return arr;
    }
    return [];
  } catch (err) {
    console.warn('[WARN] Could not parse latestMeasurements.json:', err.message);
    return [];
  }
}

function writeMeasurementsFile(arr) {
  fs.writeFileSync(MEASUREMENTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
}

/**
 * Remove any measurements from previous days.
 * We'll keep only items whose local date is "today" (based on local time).
 */
function purgeOldMeasurements(arr) {
  const now = new Date();
  const todayStr = now.toLocaleDateString(); // e.g. "1/29/2025"
  return arr.filter((m) => {
    const d = new Date(m.Timestamp);
    return d.toLocaleDateString() === todayStr;
  });
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Crypto + region updates
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function updateBaseURL(region) {
  baseURL = 'https://api.libreview.io';
//  baseURL = `https://api-${region}.libreview.io`;
  apiClient.defaults.baseURL = baseURL;
  console.log('[INFO] Updated baseURL =>', baseURL);
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Login flow
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
async function doLoginFlow(email, password) {
  let respData = await postLogin(email, password);

  // region redirect => re-login
  while (respData?.data?.redirect) {
    const region = respData.data.region;
    if (!region) {
      throw new Error('redirect=true but no region specified');
    }
    updateBaseURL(region);
    respData = await postLogin(email, password);
  }

  // status=4 => T&C acceptance
  while (respData?.status === 4) {
    respData = await doAuthContinue(respData);
  }

  if (respData?.status !== 0) {
    console.error('[DEBUG] login response:', JSON.stringify(respData, null, 2));
    throw new Error(`Login flow did not reach status=0 (got ${respData?.status}).`);
  }

  const token = respData.data.authTicket.token;
  const userId = respData.data.user.id;
  const accountIdHash = sha256Hex(userId);

  console.log('[INFO] doLoginFlow => success, userId:', userId);
  return { token, userId, accountIdHash };
}

async function postLogin(email, password) {
  console.log(`[INFO] Logging in at ${baseURL}/llu/auth/login`);
  const body = { email, password };
  const res = await apiClient.post('/llu/auth/login', body);
  return res.data;
}

async function doAuthContinue(prevResponse) {
  const stepType = prevResponse.data.step?.type;
  const token = prevResponse.data.authTicket?.token;
  if (!stepType || !token) {
    throw new Error('Missing step type or token for status=4');
  }
  console.log(`[INFO] Additional step => /auth/continue/${stepType}`);
  const headers = { Authorization: `Bearer ${token}` };
  const res = await apiClient.post(`/auth/continue/${stepType}`, {}, { headers });
  return res.data;
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Arrow logic
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function arrowToEmoji(num) {
  switch (num) {
    case 1: return '⬇️';
    case 2: return '↘️';
    case 3: return '➡️';
    case 4: return '↗️';
    case 5: return '⬆️';
    default: return '❓';
  }
}

function computeSinceLastTrendArrowNumber(diff) {
  if (diff === 0)           return 3; // stable
  if (diff > 0 && diff <= 5)  return 4; // slight up
  if (diff > 5)              return 5; // up
  if (diff < 0 && diff >= -5) return 2; // slight down
  return 1; // down
}

/**
 * MeasurementColor to Name
 * 1 => "green"
 * 2 => "yellow"
 * 3 => "orange"
 * 4 => "red"
 */
function measurementColorName(num) {
  switch (num) {
    case 1: return 'green';
    case 2: return 'yellow';
    case 3: return 'orange';
    case 4: return 'red';
    default: return 'unknown';
  }
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// parseLibreTimestamp(ts) => Date
// "1/5/2025 10:33:54 PM" => JavaScript Date
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function parseLibreTimestamp(ts) {
  // e.g. "1/5/2025 10:33:54 PM"
  const [datePart, timePart, ampm] = ts.split(' ');
  const [month, day, year] = datePart.split('/');
  const [hh, mm, ss] = timePart.split(':');

  let hour = parseInt(hh, 10);
  const minute = parseInt(mm, 10);
  const second = parseInt(ss, 10);

  if (ampm.toUpperCase() === 'PM' && hour < 12) hour += 12;
  if (ampm.toUpperCase() === 'AM' && hour === 12) hour = 0;

  // new Date(year, monthIndex, day, hour, minute, second)
  return new Date(+year, +month - 1, +day, hour, minute, second);
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// scheduleNextFetch(lastTimestampString):
//   - parse lastTimestamp into a Date
//   - add 60 seconds
//   - add offset
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function scheduleNextFetch(lastTimestamp) {
  const offsetSeconds = 3;
  const lastDate = new Date(lastTimestamp);
  const nextDate = new Date(lastDate.getTime() + 60_000);
  const finalDate = new Date(nextDate.getTime() + offsetSeconds * 1000);

  const now = new Date();
  let delayMs = finalDate - now;
  if (delayMs < 1000) {
    delayMs = 30_000;
  }

  console.log(`[DEBUG] Last reading timestamp: ${lastTimestamp}`);
  console.log(`[DEBUG] Scheduling next fetch ~ ${finalDate.toLocaleTimeString()} => ${delayMs}ms`);
  return delayMs;
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// fetchAndStoreMeasurement
//  1) ensures login
//  2) fetches latest measurement => "1/5/2025 10:33:54 PM" style
//  3) parse => ISO string
//  4) store => memoryData
//  5) return isoStamp for scheduling
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

// Modified section to include patientId caching

async function fetchAndStoreMeasurement() {
  const cacheObj = readCache();

  // Ensure token, userId, accountIdHash, and patientId are cached
  if (!cacheObj.token || !cacheObj.userId || !cacheObj.accountIdHash) {
    console.log('[INFO] No valid token => prompting for credentials...');
    const email = await askQuestion('LibreView Email: ');
    const password = await askQuestion('LibreView Password: ');
    const { token, userId, accountIdHash } = await doLoginFlow(email, password);
    cacheObj.token = token;
    cacheObj.userId = userId;
    cacheObj.accountIdHash = accountIdHash;
    writeCache(cacheObj);
  } else {
    console.log('[INFO] Using cached token/userId...');
  }

  // Attach headers
  apiClient.defaults.headers.common['Authorization'] = `Bearer ${cacheObj.token}`;
  apiClient.defaults.headers.common['Account-Id'] = cacheObj.accountIdHash;

  // Fetch patientId and additional info if not cached
  if (!cacheObj.patientId) {
    console.log('[INFO] No cached patientId, fetching from /llu/connections...');
    const connectionsResp = await apiClient.get('/llu/connections');
    if (connectionsResp.data.status !== 0) {
      throw new Error(`Fetching /llu/connections => status=${connectionsResp.data.status}`);
    }
    const connections = connectionsResp.data.data || [];
    if (!connections.length) {
      console.log('[WARN] No connections found!');
      return null;
    }

    const { patientId, firstName, lastName, sensor } = connections[0];
    cacheObj.patientId = patientId;
    cacheObj.firstName = firstName;
    cacheObj.lastName = lastName;
    cacheObj.sensor = sensor; // Cache the full sensor object
    writeCache(cacheObj);
  } else {
    console.log(`[INFO] Using cached patientId: ${cacheObj.patientId}`);
  }

  // Update memoryData with patient and sensor info
  memoryData.patientInfo = {
    firstName: cacheObj.firstName,
    lastName: cacheObj.lastName,
    patientId: cacheObj.patientId
  };

  if (cacheObj.sensor) {
    const sensorDate = new Date(cacheObj.sensor.a * 1000);
    const deviceName =
      cacheObj.sensor.pt === 4 ? 'Freestyle Libre 3' :
      cacheObj.sensor.pt === 1 ? 'Freestyle Libre 2' :
      cacheObj.sensor.pt === 0 ? 'Freestyle Libre 1' : 'Unknown';

    memoryData.sensorInfo = {
      sn: cacheObj.sensor.sn,
      activationUnix: cacheObj.sensor.a,
      activationDateStr: sensorDate.toLocaleString(),
      ptName: deviceName
    };
  } else {
    memoryData.sensorInfo = null; // Ensure it's cleared if not available
  }

  // Use the cached patientId to fetch the latest measurement
  const patientId = cacheObj.patientId;
  const cgmResp = await apiClient.get(`/llu/connections/${patientId}/graph`);
  if (cgmResp.data.status !== 0) {
    throw new Error(`CGM data => status=${cgmResp.data.status}`);
  }

  const cgmData = cgmResp.data.data;
  const latest = cgmData?.connection?.glucoseMeasurement;
  if (!latest) {
    console.log('[WARN] No latest measurement from server!');
    return null;
  }

  // Process latest measurement and store it
  const rawTs = latest.Timestamp;
  const parsedDate = parseLibreTimestamp(rawTs);
  const isoStamp = parsedDate.toISOString();

  let measurementsArr = readMeasurementsFile();
  measurementsArr = purgeOldMeasurements(measurementsArr);

  measurementsArr.push({
    Timestamp: isoStamp,
    ValueInMgPerDl: latest.ValueInMgPerDl,
    TrendArrow: latest.TrendArrow
  });
  writeMeasurementsFile(measurementsArr);

  memoryData.measurementMgdl = {
    Timestamp: isoStamp,
    ValueInMgPerDl: latest.ValueInMgPerDl,
    TrendArrow: latest.TrendArrow,
    TrendArrowEmoji: arrowToEmoji(latest.TrendArrow)
  };

  const mmolVal = Math.round((latest.ValueInMgPerDl / 18) * 10) / 10;
  memoryData.measurementMmol = {
    Timestamp: isoStamp,
    ValueInMmolPerL: mmolVal,
    TrendArrow: latest.TrendArrow,
    TrendArrowEmoji: arrowToEmoji(latest.TrendArrow)
  };

  return isoStamp;
}



// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// Start HTTPS server
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
function startHttpsServer() {
  const app = express();
  const PORT = 8443; // or 8443 if you prefer

  // /patient-info
  app.get('/patient-info', (req, res) => {
    if (!memoryData.patientInfo) {
      return res.status(404).json({ error: 'No patient info available' });
    }
    return res.json(memoryData.patientInfo);
  });

  // /sensor-info
  app.get('/sensor-info', (req, res) => {
    if (!memoryData.sensorInfo) {
      return res.status(404).json({ error: 'No sensor info available' });
    }
    return res.json(memoryData.sensorInfo);
  });

  // /measurement-mgdl
  app.get('/measurement-mgdl', (req, res) => {
    if (!memoryData.measurementMgdl) {
      return res.status(404).json({ error: 'No mg/dL measurement available' });
    }
    return res.json(memoryData.measurementMgdl);
  });

  // /measurement-mmol
  app.get('/measurement-mmol', (req, res) => {
    if (!memoryData.measurementMmol) {
      return res.status(404).json({ error: 'No mmol measurement available' });
    }
    return res.json(memoryData.measurementMmol);
  });

  const server = https.createServer(sslOptions, app);
  server.listen(PORT, () => {
    console.log(`[INFO] HTTPS server running on port ${PORT}`);
    console.log(`Try: https://<your-raspi-ip>:${PORT}/patient-info`);
  });
}

// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
// The main "cycle" logic:
// fetchAndStoreMeasurement(), then schedule next fetch
// ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
async function fetchCycle() {
  try {
    const lastTimestamp = await fetchAndStoreMeasurement();
    if (!lastTimestamp) {
      console.log('[WARN] No lastTimestamp => scheduling next fetch in 60s');
      setTimeout(fetchCycle, 60_000);
      return;
    }
    const ms = scheduleNextFetch(lastTimestamp);
    console.log(`[INFO] Next fetch in ${(ms / 1000).toFixed(1)}s`);
    setTimeout(fetchCycle, ms);
  } catch (err) {
    console.error('[ERROR] fetchCycle failed:', err.message);
    setTimeout(fetchCycle, 60_000);
  }
}

async function main() {
  startHttpsServer();
  await fetchCycle();
}

main().catch((err) => {
  console.error('[ERROR] main failed:', err.message);
});
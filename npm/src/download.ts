import { getToolName, getToolUrl, isGithubActions, logger } from './tools';
import { execSync } from 'child_process';
import * as core from "@actions/core";
import * as toolcache from '@actions/tool-cache';
import * as fs from 'fs';
import * as os from 'os';
import * as https from 'https';
// import { awaitSync } from '@kaciras/deasync';
// import { createWorker } from 'await-sync';
// import { runAsWorker } from 'synckit';
import * as deasync from 'deasync';

export function ossignInPath(): boolean {
    const binary = process.platform == "win32" ? "ossign.exe" : "ossign";
    const whichCmd = process.platform == "win32" ? "where.exe" : "which";
    
    try {
        execSync(`${whichCmd} ${binary}`, { stdio: 'ignore' });
        logger(`${binary} found in PATH`);
        return true;
    } catch (error) {
        logger(`${binary} not found in PATH`);
        return false;
    }
}


export async function DownloadBinary(version: string = "latest"): Promise<string> {
    const binary = getToolName();
    const url = getToolUrl(version);

    logger(`Downloading binary from ${url}`);

    if (isGithubActions()) {
        const inCache = toolcache.find(binary, version, process.arch);
        if (inCache) {
            logger(`Found ${binary} in cache at ${inCache}`);
            core.addPath(inCache);
            return inCache;
        }


        logger(`Downloading ${binary} from ${url}...`);
        const downloadPath = await toolcache.downloadTool(url);
        if (!downloadPath) {
            throw new Error(`Failed to download ${binary}`);
        }

        const cachePath = await toolcache.cacheFile(downloadPath, process.platform == "win32" ? "ossign.exe" : "ossign", binary, version, process.arch);
        if (!cachePath) {
            throw new Error(`Failed to cache ${binary}`);
        }

        if (process.platform !== "win32") {
            fs.chmodSync(`${cachePath}/ossign`, 0o755);
        }

        core.addPath(cachePath);
        return process.platform == "win32" ? `ossign.exe` : `ossign`;
    }

    // Get year-month-day string for unique temp dir
    const dayMonthYear = new Date().toISOString().split('T')[0];
    
    const tempDir = `${os.tmpdir()}/ossign-${process.platform}-${process.arch}-${dayMonthYear}`
    fs.mkdirSync(tempDir, { recursive: true });
    
    const targetPath = `${tempDir}/${process.platform == "win32" ? "ossign.exe" : "ossign"}`;

    // If target path exists, success
    if (fs.existsSync(targetPath)) {
        logger(`${binary} already exists at ${targetPath}`);
        return targetPath;
    }

    logger(`Downloading ${binary} to temporary path ${targetPath}...`);

    const downloadPath = await toolcache.downloadTool(url, targetPath);
    if (!downloadPath) {
        throw new Error(`Failed to download ${binary}`);
    }

    if (process.platform !== "win32") {
        fs.chmodSync(downloadPath, 0o755);
    }

    logger(`${binary} downloaded to ${downloadPath}`);

    return downloadPath;
}

export const DownloadBinarySync = require('deasync')(DownloadBinary) as (version?: string) => string;

// export const DownloadBinarySync = createSyncFn(DownloadBinary, {
//     tsRunner: 'tsx'
// });

// export function DownloadBinarySync(version: string = "latest"): string {
//     return awaitSync(DownloadBinary(version));
// }

// function download(url: string, targetPath: string): Promise<string> {
//     return new Promise((resolve, reject) => {
//         const file = fs.createWriteStream(targetPath, { mode: 0o755 });
//         https.get(url, (response) => {
//             response.pipe(file);
//             file.on('finish', () => {
//                 file.close();
//                 resolve(targetPath);
//             });
//         }).on('error', (err) => {
//             fs.unlinkSync(targetPath);
//             reject(err);
//         });
//     });
// }

// export function DownloadBinarySync(version: string = "latest"): string {
//     const binary = getToolName();
//     const url = getToolUrl(version);

//     logger(`Downloading binary from ${url}`);

//     // Get year-month-day string for unique temp dir
//     const dayMonthYear = new Date().toISOString().split('T')[0];
    
//     const tempDir = `${os.tmpdir()}/ossign-${process.platform}-${process.arch}-${dayMonthYear}`
//     fs.mkdirSync(tempDir, { recursive: true });
    
//     const targetPath = `${tempDir}/${process.platform == "win32" ? "ossign.exe" : "ossign"}`;

//     // If target path exists, success
//     if (fs.existsSync(targetPath)) {
//         logger(`${binary} already exists at ${targetPath}`);
//         return targetPath;
//     }

//     logger(`Downloading ${binary} to temporary path ${targetPath}...`);


//     const downloadPath = awaitSync(download(url, targetPath));
    
//     if (process.platform !== "win32") {
//         fs.chmodSync(downloadPath, 0o755);
//     }

//     logger(`${binary} downloaded to ${downloadPath}`);

//     return downloadPath;
// }
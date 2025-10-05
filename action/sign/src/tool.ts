import * as core from "@actions/core";
import * as github from "@actions/github";
import * as toolcache from '@actions/tool-cache';

const platformTranslations: { [key: string]: string } = {
    'win32': 'Windows',
    'linux': 'Linux',
    'darwin': 'Darwin'
};

const archTranslations: { [key: string]: string } = {
    'x64': 'x86_64',
    'arm64': 'arm64',
    'ia32': 'i386'
};

export async function FindLatestToolVersion() : Promise<string> {
    core.info("Finding latest ossign version...");
    const token = core.getInput("token");
    core.info("Using provided GitHub token to fetch latest release");
    
    if (!token || token.trim() === "") {
        throw new Error("GitHub token is required to fetch latest release");
    }
    const response = await github.getOctokit(token).rest.repos.getLatestRelease({
        owner: "ossign",
        repo: "ossign",
    });

    core.info(`Latest release response: ${JSON.stringify(response.data)}`);

    const tagName = response.data.tag_name;
    if (!tagName) {
        throw new Error("Could not find latest release tag");
    }

    core.info(`Latest release tag is ${tagName}`);

    return tagName;
}

export async function GetBinary(version: string) : Promise<string> {
    const platform = platformTranslations[process.platform] || "invalid";
    const arch = archTranslations[process.arch] || "invalid";
    
    if (platform === "invalid" || arch === "invalid") {
        throw new Error(`Unsupported platform/architecture: ${process.platform}/${process.arch}`);
    }

    const inCache = await toolcache.find(`ossign-${platform}`, version, process.arch);
    if (inCache) {
        core.info(`Found ossign in cache at ${inCache}`);
        core.addPath(inCache);
        return inCache;
    }

    const downloadUrl = `https://github.com/ossign/ossign/releases/download/${version}/ossign_${platform}_${arch}${platform === "Windows" ? ".exe" : ""}`;
    core.info(`Downloading ossign from ${downloadUrl}...`);
    
    const downloadPath = await toolcache.downloadTool(downloadUrl);
    if (!downloadPath) {
        throw new Error("Failed to download ossign binary");
    }

    const cacheName = `ossign-${platform}`;
    const cachePath = await toolcache.cacheFile(downloadPath, platform === "Windows" ? "ossign.exe" : "ossign", cacheName, version, process.arch);

    if (!cachePath) {
        throw new Error("Failed to cache ossign binary");
    }

    core.addPath(cachePath);
    return cachePath;
}

export async function InstallOssign() : Promise<string> {
    const version = await FindLatestToolVersion();
    core.info(`Latest ossign version is ${version}`);
    const binaryPath = await GetBinary(version);
    core.info(`ossign installed at ${binaryPath}`);
    return binaryPath;
}
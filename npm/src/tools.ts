import * as core from "@actions/core";
// import * as github from "@actions/github";
// import * as toolcache from '@actions/tool-cache';
// import * as io from '@actions/io';
import { exec } from "@actions/exec";

export function isGithubActions(): boolean {
    return process.env.GITHUB_ACTIONS !== undefined;
}

export function logger(message: string, level: "info" | "warning" | "error" = "info"): void {
    switch (level) {
        case "info":
            isGithubActions() ? core.info(message) : console.log(message);
            break;
        case "warning":
            isGithubActions() ? core.warning(message) : console.warn(message);
            break;
        case "error":
            isGithubActions() ? core.error(message) : console.error(message);
            break;
        default:
            console.log(message);
    }
}

export function getToolName(): string {
    const platform = process.platform.substring(0, 1).toUpperCase() + process.platform.substring(1);
    const arch = process.arch == "arm64" ? "arm64" : "x86_64";
    let suffix = "";
    
    if (platform === "Windows") {
        suffix = ".exe";
    }

    logger(`Detected platform: ${platform}, architecture: ${arch}`);
    logger(`Getting ossign_${platform}_${arch}${suffix}`);

    return `ossign_${platform}_${arch}${suffix}`;
}

export function getToolUrl(version: string = "latest"): string {
    const toolName = getToolName();
    if (version === "latest") {
        return "https://github.com/ossign/ossign/releases/latest/download/" + toolName;
    }

    return "https://github.com/ossign/ossign/releases/download/" + version + "/" + toolName;
}
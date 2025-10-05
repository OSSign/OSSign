import * as core from "@actions/core";
import { InstallOssign } from "./tool.ts";
import * as fs from "fs/promises";
import * as exec from "@actions/exec";

async function InstallConfig() : Promise<string> {
    const config = core.getInput("config");

    if (!config || config.trim() === "" || config.length < 10) {
        core.info("No config provided, skipping config installation");
        return "";
    }

    const platform = process.platform;

    let configPath = "";

    if (platform === "win32") {
        configPath = `${process.env["USERPROFILE"]}\\ossign\\config.yaml`;
        core.info(`Writing config to ${configPath}...`);
        await fs.mkdir(`${process.env["USERPROFILE"]}\\ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    } else {
        configPath = `${process.env["HOME"]}/.ossign/config.yaml`;
        core.info(`Writing config to ${configPath}...`);
        await fs.mkdir(`${process.env["HOME"]}/.ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    }

    return configPath;
}

   
export async function run() {
    const config = core.getInput("config");
    const installOnly = core.getInput("install_only").toLowerCase() === "true";

    let configPath = "";

    if (config && config.trim() !== "") {
        core.info("Using provided ossign config");
        configPath = await InstallConfig();
    }

    const binaryPath = await InstallOssign();
    core.info("OSSign Binary has been successfully installed");
    core.setOutput("ossignPath", binaryPath);
    core.setOutput("configPath", configPath);
    if (installOnly) {
        
        return;
    }

    const resp = await exec.exec(binaryPath, ["--help"]);
    core.info(`ossign --help exited with code ${resp}`);

    
//     const inputFile = core.getInput("inputFile");
//     const outputFile = core.getInput("outputFile");
//     const fileType = core.getInput("fileType");




//     const username = core.getInput("username");
//     const token = core.getInput("token");
//     const dispatch_only = core.getInput("dispatch_only").toLowerCase() === "true";
//     const single_check = core.getInput("single_check");

//     if (!username || username.trim() === "") {
//         core.setFailed("Username is required");
//         return;
//     }

//     if (!token || token.trim() === "") {
//         core.setFailed("Token is required");
//         return;
//     }
//   core.setOutput("finished", true);
//     core.info(`Triggering workflow dispatch for ${ref_name} in ${github.context.repo.repo}...`);
// //             return true;
//     // core.info("Workflow not completed yet.");
//         core.setOutput("signed_artifacts", "");
//         core.setOutput("finished", false);
}
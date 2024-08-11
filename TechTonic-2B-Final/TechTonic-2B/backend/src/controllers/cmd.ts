import { Request, Response } from "express";
import { spawn } from 'child_process';

export const cmdExecutor = async (req: Request, res: Response) => {
    try {
        const command = "cd /home/ayush/TechTonic-2B/backend/volatility3; python3 vol.py -f /home/ayush/TechTonic-2B/backend/memory_dumps/charlie-2009-11-23.mddramimage windows.pstree.PsTree"

        try {
            const childProcess = spawn(command, {
                shell: true,
                stdio: ['ignore', 'pipe', 'pipe'] // Ignoring stdin, piping stdout and stderr
            });

            childProcess.stdout.pipe(res); // Stream stdout directly to response
            childProcess.stderr.pipe(res); // Stream stderr directly to response

            childProcess.on('close', (code) => {
                console.log(`Child process exited with code ${code}`);
                res.end(); // End response when process finishes
            });
        } catch (err) {
            res.status(500).json({ error: err });
        }
    } catch (error) {
        res.status(400).send({ error: "Error creating user" });
    }
};
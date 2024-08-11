import express from "express";
import { cmdExecutor } from "@controllers/cmd";
import { createNewAnalyze, getAllAnalysisResult, getAnalysisResult } from "@controllers/analyze";
import { getAllFilesList, createNewFile } from "@controllers/files";

const router = express.Router();

router.post("/get-result", cmdExecutor);

router.post("/memory-dump", createNewFile);
router.get("/memory-dump", getAllFilesList);

router.post("/analyze", createNewAnalyze);
router.get("/analysis/:analysisId/result", getAnalysisResult);

router.get("/analysis", getAllAnalysisResult);

export default router;
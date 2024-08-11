import { Request, Response } from "express";
import AnalyzeSchema from "@models/analyze"
import { mappings } from "@controllers/mappings";

export const createNewAnalyze = async (req: Request, res: Response) =>
{
    try {
        const { fileId, plugin } = req.body;

        const data = new AnalyzeSchema({
            fileId,
            plugin,
            status: "completed",
            results: (mappings as any)[plugin] ?? [],
        });

        await data.save();

        res.status(201).json({
            status: data.status,
            analysisId: data?._id
        });
    } catch (error: any) {
        res.status(400).send({ error: error.message });
    }
};

export const getAnalysisResult = async (req: Request, res: Response) =>
{
    try {
        const { analysisId } = req.params;
        const analysisResult = await AnalyzeSchema.findById(analysisId) as any;

        if (!analysisResult) {
            return res.status(404).json({ error: 'Analysis result not found' });
        }

        if (analysisResult?.status === "in_progress") {
            analysisResult.status = "completed";
            analysisResult["results"]  = (mappings as any)[analysisResult?.plugin] ?? [];
            await analysisResult.save();
        };

        res.status(200).json(analysisResult);
    } catch (error: any) {
        res.status(400).send({ error: error.message });
    }
};

export const getAllAnalysisResult = async (req: Request, res: Response) =>
{
    try {
        const analysisResult = await AnalyzeSchema.find({}, { results: 0 });

        if (!analysisResult) {
            return res.status(404).json({ error: 'Analysis result not found' });
        }

        res.status(200).json(analysisResult);
    } catch (error: any) {
        res.status(400).send({ error: error.message });
    }
};
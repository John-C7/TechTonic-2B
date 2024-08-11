import { Request, Response } from "express";
import FileSchema from "@models/files"

export const createNewFile = async (req: Request, res: Response) => {
    try {
        const { file_name, file_id } = req.body;

        const user = new FileSchema({
            file_name,
            file_id,
        });

        await user.save();
        res.status(201).json(user);
    } catch (error) {
        res.status(400).send({ error: "Error creating user" });
    }
};

export const getAllFilesList = async (req: Request, res: Response) =>
{
    try {
        const filesList = await FileSchema.find();
        res.status(200).json(filesList);
    } catch (error: any) {
        res.status(400).send({ error: error.message });
    }
};
import mongoose, { Schema, Document } from "mongoose";

interface IUser extends Document {
    fileId: string;
    plugin: string;
    status: string;
}

const AnalyzeSchema: Schema = new Schema({
    fileId: { type: String, required: true },
    plugin: { type: String, required: true },
    memoryProfile: { type: String, required: true, default: "Win7SP1x86_23418" },
    createdAt: { type: Date, required: true, default: Date.now },
    status: { type: String, required: true, default: "in_progress" },
    results: { type: Schema.Types.Mixed, required: true, default: [] },
});

const AnalyzeModel = mongoose.model<IUser>("analyze", AnalyzeSchema);

export default AnalyzeModel;
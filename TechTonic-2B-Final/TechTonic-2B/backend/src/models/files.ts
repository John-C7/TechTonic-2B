import mongoose, { Schema, Document } from "mongoose";

interface IUser extends Document {
    file_name: string;
    file_id: string;
}

const FileSchema: Schema = new Schema({
    file_name: { type: String, required: true },
    file_id: { type: String, required: true },
});

const FileModel = mongoose.model<IUser>("Files", FileSchema);

export default FileModel;
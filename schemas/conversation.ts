import { Schema } from "mongoose";

export interface IConversation {
	_id?: string;
	id: string;
	createdTimestamp: number;
	verify: string;
}

const schema = new Schema<IConversation>(
	{
		id: {
			type: String,
			required: true,
			unique: true
		},
		createdTimestamp: {
			type: Number,
			required: true,
			unique: false
		},
		verify: {
			type: String,
			required: true,
			unique: true
		}
	},
	{
		strictQuery: true
	}
);

export default schema;

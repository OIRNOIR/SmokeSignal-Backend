import { Schema } from "mongoose";

export interface IInviteCode {
	_id?: string;
	code: string;
	createdTimestamp: number;
	requestedTimestamp: number;
	expirationTimestamp: number;
}

const schema = new Schema<IInviteCode>(
	{
		code: {
			type: String,
			required: true,
			unique: true
		},
		createdTimestamp: {
			type: Number,
			required: true,
			unique: false
		},
		requestedTimestamp: {
			type: Number,
			required: true,
			unique: true
		},
		expirationTimestamp: {
			type: Number,
			required: true,
			default: 0
		}
	},
	{
		strictQuery: true
	}
);

export default schema;

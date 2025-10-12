import { Schema } from "mongoose";

export interface IMessage {
	_id?: string;
	id: bigint;
	createdTimestamp: number;
	editedTimestamp: number | null;
	recipientId: string;
	senderId: string;
	conversationId?: string;
	eContent: string;
	nonce?: string;
	type: string;
}

const schema = new Schema<IMessage>(
	{
		id: {
			type: Schema.Types.BigInt,
			required: true,
			unique: true
		},
		createdTimestamp: {
			type: Number,
			required: true
		},
		editedTimestamp: {
			type: Number,
			required: false,
			default: null
		},
		recipientId: {
			type: String,
			required: true
		},
		senderId: {
			type: String,
			required: true
		},
		conversationId: {
			type: String
		},
		eContent: {
			type: String,
			required: true
		},
		nonce: {
			type: String
		},
		type: {
			type: String,
			required: true
		}
	},
	{
		strictQuery: true
	}
);

export default schema;

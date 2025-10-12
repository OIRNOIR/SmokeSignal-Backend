import { Schema } from "mongoose";

export interface IUser {
	_id?: string;
	id: string;
	createdTimestamp: number;
	lastConnectionTimestamp: number;
	keys: {
		Kyber: {
			publicKey: string;
		};
	};
	usernameEncrypted: string;
	conversations: {
		id?: string;
		eVerify?: string;
		eKeyStore?: string;
		eUserIDs?: string;
		eLastViewed?: string;
	}[];
	eProfileStore?: string;
}

const schema = new Schema<IUser>(
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
		lastConnectionTimestamp: {
			type: Number,
			required: true,
			unique: false
		},
		keys: {
			Kyber: {
				publicKey: {
					type: String,
					required: true,
					unique: true
				}
			}
		},
		usernameEncrypted: {
			type: String,
			required: true,
			unique: false
		},
		conversations: [
			{
				id: String,
				eVerify: String,
				eKeyStore: String,
				eUserIDs: String,
				eLastViewed: String
			}
		],
		eProfileStore: {
			type: String,
			required: false,
			default: null
		} // For storing others' profile data
	},
	{
		strictQuery: true
	}
);

export default schema;

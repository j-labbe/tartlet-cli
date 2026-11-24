import { z } from "zod";

export const PersonIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/).refine((value) => !value.includes("..")).brand<"PersonId">();
export const VmNameSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/).brand<"VmName">();
export const WorkerNameSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/).brand<"WorkerName">();
export const TaskLabelSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,15}$/).brand<"TaskLabel">();
export const ServerIdSchema = z.string().regex(/^srv_[a-z2-7]{26}$/).brand<"ServerId">();
export const OrganizationIdSchema = z.string().regex(/^org_[a-z2-7]{26}$/).brand<"OrganizationId">();
export const CloudAccountIdSchema = z.string().regex(/^acct_[a-z2-7]{26}$/).brand<"CloudAccountId">();
export const GrantTagSchema = z.string().regex(/^grt_[a-z2-7]{26}$/).brand<"GrantTag">();
export const JobIdSchema = z.string().regex(/^job_[a-z2-7]{26}$/).brand<"JobId">();
export const ClientRequestIdSchema = z.string().regex(/^[A-Za-z0-9._-]{8,64}$/).brand<"ClientRequestId">();
export const CutoffIdSchema = z.string().regex(/^cut_[a-z2-7]{26}$/).brand<"CutoffId">();

export type PersonId = z.infer<typeof PersonIdSchema>;
export type VmName = z.infer<typeof VmNameSchema>;
export type WorkerName = z.infer<typeof WorkerNameSchema>;
export type TaskLabel = z.infer<typeof TaskLabelSchema>;
export type ServerId = z.infer<typeof ServerIdSchema>;
export type OrganizationId = z.infer<typeof OrganizationIdSchema>;
export type CloudAccountId = z.infer<typeof CloudAccountIdSchema>;
export type GrantTag = z.infer<typeof GrantTagSchema>;
export type JobId = z.infer<typeof JobIdSchema>;
export type ClientRequestId = z.infer<typeof ClientRequestIdSchema>;
export type CutoffId = z.infer<typeof CutoffIdSchema>;

export const isPersonId = (value: unknown): value is PersonId => PersonIdSchema.safeParse(value).success;
export const isVmName = (value: unknown): value is VmName => VmNameSchema.safeParse(value).success;
export const isWorkerName = (value: unknown): value is WorkerName => WorkerNameSchema.safeParse(value).success;
export const isTaskLabel = (value: unknown): value is TaskLabel => TaskLabelSchema.safeParse(value).success;
export const isServerId = (value: unknown): value is ServerId => ServerIdSchema.safeParse(value).success;
export const isOrganizationId = (value: unknown): value is OrganizationId => OrganizationIdSchema.safeParse(value).success;
export const isCloudAccountId = (value: unknown): value is CloudAccountId => CloudAccountIdSchema.safeParse(value).success;
export const isGrantTag = (value: unknown): value is GrantTag => GrantTagSchema.safeParse(value).success;
export const isJobId = (value: unknown): value is JobId => JobIdSchema.safeParse(value).success;
export const isClientRequestId = (value: unknown): value is ClientRequestId => ClientRequestIdSchema.safeParse(value).success;
export const isCutoffId = (value: unknown): value is CutoffId => CutoffIdSchema.safeParse(value).success;

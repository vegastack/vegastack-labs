"use client";

import { createChangeClient, createPhase5Client, createReadClient } from "@/generated/read-api";

export const readClient = createReadClient((input, init) => fetch(input, init));
export const changeClient = createChangeClient((input, init) => fetch(input, init));
export const phase5Client = createPhase5Client((input, init) => fetch(input, init));

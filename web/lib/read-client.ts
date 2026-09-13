"use client";

import { createChangeClient, createReadClient } from "@/generated/read-api";

export const readClient = createReadClient((input, init) => fetch(input, init));
export const changeClient = createChangeClient((input, init) => fetch(input, init));

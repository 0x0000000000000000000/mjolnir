/*
Copyright 2022 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import config from "../config";
import { Protection } from "./IProtection";
import { MXIDListProtectionSetting, NumberProtectionSetting, OptionListProtectionSetting } from "./ProtectionSettings";
import { Mjolnir } from "../Mjolnir";

export class TrustedReporters extends Protection {
    private recentReported = new Map<string, Set<string>>();

    settings = {
        "mxids": new MXIDListProtectionSetting(),
        "threshold": new NumberProtectionSetting(3),
        "action": new OptionListProtectionSetting(
            "alert",
            ["alert", "redact", "ban"]
        )
    };

    constructor() {
        super();
    }

    public get name(): string {
        return 'TrustedReporters';
    }
    public get description(): string {
        return "Count reports from trusted reporters and take a configured action";
    }

    public async handleReport(mjolnir: Mjolnir, roomId: string, reporterId: string, event: any, reason?: string): Promise<any> {
        if (this.settings.mxids.value.includes(reporterId)) {
            if (!this.recentReported.has(event.id)) {
                // first report we've seen recently for this event
                this.recentReported.set(event.id, new Set<string>());
                if (this.recentReported.size > 20) {
                    // queue too big. push the oldest reported event off the queue
                    const oldest = Array.from(this.recentReported)[this.recentReported.size - 1][0]
                    this.recentReported.delete(oldest);
                }
            }

            this.recentReported[event.id].add(reporterId);
            if (this.recentReported[event.id].size >= this.settings.threshold.value) {
                // reached reporting threshold

                const reporters = Array.from(this.recentReported[event.id]);
                reporters.sort();

                await mjolnir.client.sendMessage(config.managementRoom, {
                    msgtype: "m.notice",
                    body: `message ${event.id} reported by ${reporters.join(', ')}. `
                        + `action: ${this.settings.action.value}`
                });

                if (this.settings.action.value === "alert") {
                    // do nothing. just print out the report below
                } else if (this.settings.action.value === "redact") {
                    await mjolnir.client.redactEvent(roomId, event.id);
                } else if (this.settings.action.value === "ban") {
                    await mjolnir.client.banUser(event.userId, roomId);
                }
            }
        }
    }
}

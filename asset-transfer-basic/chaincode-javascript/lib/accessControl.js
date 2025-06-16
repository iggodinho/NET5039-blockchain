'use strict';

const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');
const { Contract } = require('fabric-contract-api');

class AccessControl extends Contract {

    // Create and assign a policy to multiple devices
    async CreatePolicy(ctx, policyID, objectsListJSON, role, accessHours, objectLocation, policyExpiration, maxRequestsPerHour, notifyOnAccess, userLocation, allowCloudExport) {
        const objectsList = JSON.parse(objectsListJSON);

        const policy = {
            PolicyID: policyID,
            ObjectsList: objectsList,
            Role: role,
            AccessHours: accessHours,
            ObjectLocation: objectLocation,
            PolicyExpiration: policyExpiration,
            MaxRequestsPerHour: maxRequestsPerHour,
            NotifyOnAccess: notifyOnAccess === 'true',
            UserLocation: userLocation,
            AllowCloudExport: allowCloudExport === 'true',
        };

        await ctx.stub.putState(`policy_${policyID}`, Buffer.from(stringify(sortKeysRecursive(policy))));

        for (const objID of objectsList) {
            const buffer = await ctx.stub.getState(objID);
            if (!buffer || buffer.length === 0) continue;

            const device = JSON.parse(buffer.toString());
            if (!device.PolicyIDList) device.PolicyIDList = [];

            if (!device.PolicyIDList.includes(policyID)) {
                device.PolicyIDList.push(policyID);
                await ctx.stub.putState(objID, Buffer.from(stringify(sortKeysRecursive(device))));
            }
        }

        return `Policy ${policyID} successfully created and assigned to ${objectsList.length} objects.`;
    }

    // Read a specific policy by ID
    async ReadPolicy(ctx, policyID) {
        const buffer = await ctx.stub.getState(`policy_${policyID}`);
        if (!buffer || buffer.length === 0) {
            throw new Error(`Policy ${policyID} does not exist.`);
        }
        return buffer.toString();
    }

    // List all policies in ledger
    async GetAllPolicies(ctx) {
        const results = [];
        const iterator = await ctx.stub.getStateByRange('', '');
        let result = await iterator.next();

        while (!result.done) {
            try {
                const str = result.value.value.toString('utf8');
                const json = JSON.parse(str);
                if (json.PolicyID) {
                    results.push(json);
                }
            } catch (err) {
                console.error(`Error parsing record: ${err}`);
            }
            result = await iterator.next();
        }

        await iterator.close();
        return JSON.stringify(results);
    }

    // Revoke policy: remove from devices and delete the policy
    async RevokePolicy(ctx, policyID) {
        const policyBuffer = await ctx.stub.getState(`policy_${policyID}`);
        if (!policyBuffer || policyBuffer.length === 0) {
            throw new Error(`Policy ${policyID} not found.`);
        }

        const policy = JSON.parse(policyBuffer.toString());

        for (const objID of policy.ObjectsList) {
            const buffer = await ctx.stub.getState(objID);
            if (!buffer || buffer.length === 0) continue;

            const device = JSON.parse(buffer.toString());
            if (device.PolicyIDList) {
                device.PolicyIDList = device.PolicyIDList.filter(id => id !== policyID);
                await ctx.stub.putState(objID, Buffer.from(stringify(sortKeysRecursive(device))));
            }
        }

        await ctx.stub.deleteState(`policy_${policyID}`);
        return `Policy ${policyID} successfully revoked and removed.`;
    }

    // Update any attributes of a policy
    async UpdatePolicy(ctx, policyID, updatedFieldsJSON) {
        const policyBuffer = await ctx.stub.getState(`policy_${policyID}`);
        if (!policyBuffer || policyBuffer.length === 0) {
            throw new Error(`Policy ${policyID} not found.`);
        }

        const policy = JSON.parse(policyBuffer.toString());
        const updates = JSON.parse(updatedFieldsJSON);

        for (const key of Object.keys(updates)) {
            if (key in policy) {
                policy[key] = updates[key];
            }
        }

        await ctx.stub.putState(`policy_${policyID}`, Buffer.from(stringify(sortKeysRecursive(policy))));
        return `Policy ${policyID} successfully updated.`;
    }

    async ValidateAccessRequest(ctx, objectID, role, timestamp, userLocation) {
        const buffer = await ctx.stub.getState(objectID);
        if (!buffer || buffer.length === 0) {
            throw new Error(`Device ${objectID} not found`);
        }

        const device = JSON.parse(buffer.toString());

        if (!device.PolicyIDList || device.PolicyIDList.length === 0) {
            throw new Error(`No policies associated with the device ${objectID}`);
        }

        for (const policyID of device.PolicyIDList) {
            const policyBuffer = await ctx.stub.getState(`policy_${policyID}`);
            if (!policyBuffer || policyBuffer.length === 0) continue;

            const policy = JSON.parse(policyBuffer.toString());

           
            
            if (policy.Role && policy.Role !== role) continue

            if (policy.UserLocation && policy.UserLocation !== userLocation) continue;

            if (policy.PolicyExpiration && new Date(timestamp) > new Date(policy.PolicyExpiration)) continue;

            if (policy.AccessHours) {
                const [startHour, endHour] = policy.AccessHours.split('-'); // format "08:00-18:00"
                const reqHour = new Date(timestamp).toISOString().substring(11, 16); // format "HH:MM"
                if (reqHour < startHour || reqHour > endHour) continue;
            }


            // if (policy.ObjectLocation && policy.ObjectLocation !== device.Location) continue;

            return `Access granted under policy ${policyID}`;
        }

        throw new Error(`Access denied: no policy matches the criteria for the device ${objectID}`);
    }
}

module.exports = AccessControl;

'use strict';


const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');
const { Contract } = require('fabric-contract-api');

class AssetTransfer extends Contract {

    // Inicializa el ledger con dos dispositivos de ejemplo
    async InitLedger(ctx) {
        const devices = [
            {
                ObjectID: 'device1',
                MAC: '00:11:22:33:44:55',
                PUF: 'PUF123',
                Manufacturer: 'Org1MSP',
                OwnersHistory: ['ownerA'],
                Controllers: ['ownerA'],
                DeviceType: 'smart_lock',
                FirmwareVersion: '1.0',
                RegistrationDate: "",
                LastUpdate: "",
                Status: 'active',
                Location: 'Paris',
                PolicyIDList: [],
                GatewayID: 'gateway001',
            },
            {
                ObjectID: 'device2',
                MAC: '66:77:88:99:AA:BB',
                PUF: 'PUF456',
                Manufacturer: 'Org2MSP',
                OwnersHistory: ['ownerB'],
                Controllers: ['ownerB', 'ctrlX'],
                DeviceType: 'sensor',
                FirmwareVersion: '2.0',
                RegistrationDate: "",
                LastUpdate: "",
                Status: 'active',
                Location: 'Berlin',
                PolicyIDList: [],
                GatewayID: 'gateway002',
            },
        ];

        for (const device of devices) {
            await ctx.stub.putState(device.ObjectID, Buffer.from(stringify(sortKeysRecursive(device))));
        }

        return 'InitLedger completed.';
    }

    // Registro de nuevo dispositivo (Manufacturer)
    async RegisterDevice(ctx, objectID, mac, puf, manufacturer, deviceType, firmwareVersion, gatewayID) {
        const exists = await this.DeviceExists(ctx, objectID);
        if (exists) {
            throw new Error('Device ${objectID} already exists');
        }

        const now = "";

        const device = {
            ObjectID: objectID,
            MAC: mac,
            PUF: puf,
            Manufacturer: manufacturer,
            OwnersHistory: [],
            Controllers: [],
            DeviceType: deviceType,
            FirmwareVersion: firmwareVersion,
            RegistrationDate: now,
            LastUpdate: now,
            Status: 'active',
            Location: '',
            PolicyIDList: [],
            GatewayID: gatewayID,
        };

        await ctx.stub.putState(objectID, Buffer.from(stringify(sortKeysRecursive(device))));
        return JSON.stringify(device);
    }

    // Transferencia de propiedad
    async TransferOwnership(ctx, objectID, newOwner) {
        const device = await this._getDevice(ctx, objectID);
        device.OwnersHistory.push(newOwner);
        device.Controllers = [newOwner];
        device.Status = 'active';
        device.LastUpdate = "";

        await ctx.stub.putState(objectID, Buffer.from(stringify(sortKeysRecursive(device))));
        return 'Ownership of ${objectID} transferred to ${newOwner}';
    }

    // Asignación de un controlador
    async AssignController(ctx, objectID, controllerID) {
        const device = await this._getDevice(ctx, objectID);

        if (!device.Controllers.includes(controllerID)) {
            device.Controllers.push(controllerID);
            device.LastUpdate = "updated";
            await ctx.stub.putState(objectID, Buffer.from(stringify(sortKeysRecursive(device))));
        }

        return 'Controller ${controllerID} assigned to ${objectID}';
    }

    // Revocación de un controlador
    async RevokeController(ctx, objectID, controllerID) {
        const device = await this._getDevice(ctx, objectID);
        device.Controllers = device.Controllers.filter(id => id !== controllerID);
        device.LastUpdate = "";

        await ctx.stub.putState(objectID, Buffer.from(stringify(sortKeysRecursive(device))));
        return 'Controller ${controllerID} revoked from ${objectID}';
    }

    // Marcado como inactivo
    async DeleteDevice(ctx, objectID) {
        const device = await this._getDevice(ctx, objectID);
        device.Status = 'inactive';
        device.LastUpdate = "";

        await ctx.stub.putState(objectID, Buffer.from(stringify(sortKeysRecursive(device))));
        return 'Device ${objectID} deactivated';
    }

    // Lectura individual
    async ReadDevice(ctx, objectID) {
        const device = await this._getDevice(ctx, objectID);
        return JSON.stringify(device);
    }

    // Lectura total
    async GetAllDevices(ctx) {
        const results = [];
        const iterator = await ctx.stub.getStateByRange('', '');
        let result = await iterator.next();

        while (!result.done) {
            const str = result.value.value.toString('utf8');
            try {
                const record = JSON.parse(str);
                if (record.ObjectID) {results.push(record);}
            } catch (err) {
                console.error(err);
            }
            result = await iterator.next();
        }

        return JSON.stringify(results);
    }

    // Comprobación de existencia
    async DeviceExists(ctx, objectID) {
        const buffer = await ctx.stub.getState(objectID);
        return !!(buffer && buffer.length > 0);
    }

    // Interno: obtiene el dispositivo
    async _getDevice(ctx, objectID) {
        const buffer = await ctx.stub.getState(objectID);
        if (!buffer || buffer.length === 0) {
            throw new Error('Device ${objectID} not found');
        }
        return JSON.parse(buffer.toString());
    }

    // Interno: obtiene el ID del invocador
    async _getInvoker(ctx) {
        const cid = ctx.clientIdentity.getID();
        return cid;
    }
}

module.exports = AssetTransfer;

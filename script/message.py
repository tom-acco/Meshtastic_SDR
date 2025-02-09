import json

from meshtastic import mesh_pb2, admin_pb2, telemetry_pb2

class Message(object):
    def __init__(self, sourceId, destId, data):
        self.sourceId = sourceId
        self.destId = destId

        match data.portnum:
            case 0: # UNKNOWN_APP
                self.type = "UNKNOWN_APP"

            case 1: # TEXT_MESSAGE_APP
                self.type = "TEXT_MESSAGE_APP"
                self.data = data.payload.decode("utf-8")

            case 2 : # REMOTE_HARDWARE_APP
                self.type = "REMOTE_HARDWARE_APP"

            case 3 : # POSITION_APP
                self.type = "POSITION_APP"

                pos = mesh_pb2.Position()
                pos.ParseFromString(data.payload)

                self.data = {
                    "latitude": pos.latitude_i * 1e-7,
                    "longitude": pos.longitude_i * 1e-7
                }

            case 4 : # NODEINFO_APP
                self.type = "NODEINFO_APP"

                try:
                    info = mesh_pb2.User()
                    info.ParseFromString(data.payload)
                    self.data = str(info)
                except:
                    self.data = None

            case 5 : # ROUTING_APP
                self.type = "ROUTING_APP"

                routing = mesh_pb2.Routing()
                routing.ParseFromString(data.payload)
                self.data = str(routing)

            case 6 : # ADMIN_APP
                self.type = "ADMIN_APP"

                admin = admin_pb2.AdminMessage()
                admin.ParseFromString(data.payload)
                self.data = str(admin)

            case 7 : # TEXT_MESSAGE_COMPRESSED_APP
                self.type = "TEXT_MESSAGE_COMPRESSED_APP"

            case 10 : # DETECTION_SENSOR_APP
                self.type = "DETECTION_SENSOR_APP"

            case 32 : # REPLY_APP
                self.type = "REPLY_APP"

            case 33 : # IP_TUNNEL_APP
                self.type = "IP_TUNNEL_APP"

            case 34 : # PAXCOUNTER_APP
                self.type = "PAXCOUNTER_APP"

            case 64 : # SERIAL_APP
                self.type = "SERIAL_APP"

            case 65 : # STORE_FORWARD_APP
                self.type = "STORE_FORWARD_APP"

                sfwd = mesh_pb2.StoreAndForward()
                sfwd.ParseFromString(data.payload)
                self.data = str(sfwd)

            case 67 : # TELEMETRY_APP
                self.type = "TELEMETRY_APP"

                telemetry = telemetry_pb2.Telemetry()
                telemetry.ParseFromString(data.payload)
                self.data = str(telemetry)

            case 68 : # ZPS_APP
                self.type = "ZPS_APP"

                z_info = mesh_pb2.zps()
                z_info.ParseFromString(data.payload)
                self.data = str(z_info)

            case 69 : # SIMULATOR_APP
                self.type = "SIMULATOR_APP"

            case 70 : # TRACEROUTE_APP
                self.type = "TRACEROUTE_APP"

                trct = mesh_pb2.RouteDiscovery()
                trct.ParseFromString(data.payload)
                self.data = str(trct)

            case 71 : # NEIGHBORINFO_APP
                self.type = "NEIGHBORINFO_APP"

                ninfo = mesh_pb2.NeighborInfo()
                ninfo.ParseFromString(data.payload)
                self.data = str(ninfo)

            case 72 : # ATAK_PLUGIN
                self.type = "ATAK_PLUGIN"

            case 73 : # MAP_REPORT_APP
                self.type = "MAP_REPORT_APP"

                mrpt = mesh_pb2.MapReport()
                mrpt.ParseFromString(data.payload)
                self.data = str(mrpt)

            case 74 : # POWERSTRESS_APP
                self.type = "POWERSTRESS_APP"

            case 256 : # PRIVATE_APP
                self.type = "PRIVATE_APP"

            case 257 : # ATAK_FORWARDER
                self.type = "ATAK_FORWARDER"

            case _ : # UNKNOWN 
                self.type = "UNKNOWN"

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)
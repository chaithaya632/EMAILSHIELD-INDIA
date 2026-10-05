"use client";

import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix Leaflet default icon issue in Next.js
delete (L.Icon.Default.prototype as any)._getIconUrl;

export interface GeoIPMapMarker {
  lat: number;
  lon: number;
  label: string;       // e.g., "Originating IP"
  ip: string;          // e.g., "185.220.101.5"
  role: 'origin' | 'relay' | 'destination';
  details?: string;    // e.g., "Moscow, Russia — AS48282"
}

export interface GeoIPMapProps {
  markers: GeoIPMapMarker[];
  zoom?: number;       // default 4
  height?: string;     // default "400px"
  showFlightPath?: boolean; // connect markers with lines
}

// Component to fit bounds to markers
const MapBounds = ({ markers }: { markers: GeoIPMapMarker[] }) => {
  const map = useMap();
  useEffect(() => {
    if (markers.length > 0) {
      const bounds = L.latLngBounds(markers.map(m => [m.lat, m.lon]));
      map.fitBounds(bounds, { padding: [50, 50] });
    }
  }, [map, markers]);
  return null;
};

export const GeoIPMap: React.FC<GeoIPMapProps> = ({
  markers,
  zoom = 4,
  height = "400px",
  showFlightPath = false
}) => {
  if (!markers || markers.length === 0) {
    return null;
  }

  // Calculate center: average of all marker coordinates
  const centerLat = markers.reduce((sum, m) => sum + m.lat, 0) / markers.length;
  const centerLon = markers.reduce((sum, m) => sum + m.lon, 0) / markers.length;
  const center: [number, number] = [centerLat, centerLon];

  // Polyline coordinates
  const flightPathCoords: [number, number][] = markers.map(m => [m.lat, m.lon]);

  const getMarkerColor = (role: string) => {
    switch (role) {
      case 'origin': return '#00CC96';
      case 'relay': return '#636EFA';
      case 'destination': return '#EF553B';
      default: return '#00CC96';
    }
  };

  const getMarkerRadius = (role: string) => {
    switch (role) {
      case 'origin': return 10;
      case 'relay': return 7;
      case 'destination': return 8;
      default: return 7;
    }
  };
  
  const getMarkerOpacity = (role: string) => {
    switch (role) {
      case 'origin': return 0.8;
      case 'relay': return 0.7;
      case 'destination': return 0.8;
      default: return 0.7;
    }
  }

  return (
    <div 
      className="w-full bg-[#0a0e17] border border-slate-700/50 rounded-lg overflow-hidden" 
      style={{ height }}
    >
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: '100%', width: '100%', background: '#0a0e17' }}
        scrollWheelZoom={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        />

        {showFlightPath && markers.length > 1 && (
          <Polyline
            positions={flightPathCoords}
            pathOptions={{ color: '#00BCD4', weight: 2, dashArray: '8 4' }}
          />
        )}

        {markers.map((marker, index) => (
          <CircleMarker
            key={`${marker.ip}-${index}`}
            center={[marker.lat, marker.lon]}
            radius={getMarkerRadius(marker.role)}
            pathOptions={{
              color: getMarkerColor(marker.role),
              fillColor: getMarkerColor(marker.role),
              fillOpacity: getMarkerOpacity(marker.role),
              weight: 2
            }}
          >
            <Popup className="dark-popup">
              <div className="text-slate-800 font-sans p-1">
                <div className="font-bold text-sm mb-1">{marker.label}</div>
                <div className="text-xs mb-1"><span className="font-semibold">IP:</span> {marker.ip}</div>
                {marker.details && (
                  <div className="text-xs text-slate-600">{marker.details}</div>
                )}
              </div>
            </Popup>
          </CircleMarker>
        ))}
        
        {markers.length > 1 && <MapBounds markers={markers} />}
      </MapContainer>
    </div>
  );
};

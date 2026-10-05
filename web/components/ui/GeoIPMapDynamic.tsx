"use client";
import dynamic from 'next/dynamic';

const GeoIPMap = dynamic(() => import('./GeoIPMap').then(mod => mod.GeoIPMap), {
  ssr: false,
  loading: () => (
    <div className="w-full bg-slate-800/30 border border-slate-700/50 rounded-lg flex items-center justify-center" style={{ height: '400px' }}>
      <div className="text-slate-500 text-sm">Loading GeoIP Map...</div>
    </div>
  ),
});

export { GeoIPMap as GeoIPMapDynamic };
export type { GeoIPMapMarker, GeoIPMapProps } from './GeoIPMap';

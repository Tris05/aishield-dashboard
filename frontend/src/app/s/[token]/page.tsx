import ReportView from "@/components/ReportView";
export default async function ScanPage({ params }: { params: Promise<{ token: string }> }) { const { token } = await params; return <ReportView token={token}/>; }

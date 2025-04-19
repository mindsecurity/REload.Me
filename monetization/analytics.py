# monetization/analytics.py
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
import json
import redis
from typing import Dict, List, Optional

class UsageAnalytics:
    """Track and analyze usage for billing and optimization"""
    
    def __init__(self, db_connection, redis_connection=None):
        self.db = db_connection
        self.redis = redis_connection or redis.Redis(host='localhost', port=6379, db=0)
    
    def track_analysis(self, 
                      user_id: str,
                      analysis_type: str,
                      binary_size: int,
                      duration_seconds: float,
                      success: bool,
                      features_used: List[str]) -> None:
        """Track a single analysis for billing"""
        
        data = {
            'user_id': user_id,
            'timestamp': datetime.utcnow(),
            'analysis_type': analysis_type,
            'binary_size': binary_size,
            'duration_seconds': duration_seconds,
            'success': success,
            'features_used': json.dumps(features_used),
            'api_cost': self._calculate_api_cost(analysis_type, features_used)
        }
        
        # Store in database
        self.db.execute("""
            INSERT INTO analysis_logs 
            (user_id, timestamp, analysis_type, binary_size, duration_seconds, success, features_used, api_cost)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, data['timestamp'], analysis_type, binary_size, duration_seconds, success, data['features_used'], data['api_cost']))
        
        # Update real-time metrics in Redis
        self._update_redis_metrics(user_id, analysis_type, success)
    
    def _calculate_api_cost(self, analysis_type: str, features_used: List[str]) -> float:
        """Calculate API cost for the analysis"""
        base_costs = {
            'basic_analysis': 0.01,
            'exploit_generation': 0.10,
            'dynamic_analysis': 0.05,
            'binary_diffing': 0.03
        }
        
        feature_costs = {
            'ai_assistance': 0.02,
            'custom_reports': 0.01,
            'vulnerability_scan': 0.03
        }
        
        total_cost = base_costs.get(analysis_type, 0.01)
        for feature in features_used:
            total_cost += feature_costs.get(feature, 0.0)
        
        return total_cost
    
    def _update_redis_metrics(self, user_id: str, analysis_type: str, success: bool) -> None:
        """Update real-time metrics in Redis"""
        # Daily analysis count
        today = datetime.utcnow().strftime('%Y-%m-%d')
        self.redis.incr(f'daily_analyses:{today}')
        self.redis.incr(f'user_analyses:{user_id}:{today}')
        
        # Success rate
        self.redis.incr(f'analysis_total:{analysis_type}')
        if success:
            self.redis.incr(f'analysis_success:{analysis_type}')
        
        # User monthly usage
        month = datetime.utcnow().strftime('%Y-%m')
        self.redis.incr(f'user_monthly_usage:{user_id}:{month}')
    
    def get_user_usage(self, user_id: str, period_days: int = 30) -> Dict:
        """Get usage statistics for a user"""
        start_date = datetime.utcnow() - timedelta(days=period_days)
        
        query = """
            SELECT 
                COUNT(*) as total_analyses,
                SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_analyses,
                AVG(duration_seconds) as avg_duration,
                SUM(api_cost) as total_cost,
                analysis_type,
                COUNT(DISTINCT DATE(timestamp)) as active_days
            FROM analysis_logs
            WHERE user_id = ? AND timestamp >= ?
            GROUP BY analysis_type
        """
        
        results = self.db.execute(query, (user_id, start_date)).fetchall()
        
        return {
            'total_analyses': sum(r['total_analyses'] for r in results),
            'successful_analyses': sum(r['successful_analyses'] for r in results),
            'success_rate': sum(r['successful_analyses'] for r in results) / sum(r['total_analyses'] for r in results) if results else 0,
            'avg_duration': sum(r['avg_duration'] * r['total_analyses'] for r in results) / sum(r['total_analyses'] for r in results) if results else 0,
            'total_cost': sum(r['total_cost'] for r in results),
            'active_days': max(r['active_days'] for r in results) if results else 0,
            'by_type': {r['analysis_type']: {
                'count': r['total_analyses'],
                'success_rate': r['successful_analyses'] / r['total_analyses'] if r['total_analyses'] > 0 else 0,
                'avg_duration': r['avg_duration'],
                'cost': r['total_cost']
            } for r in results}
        }
    
    def generate_revenue_report(self, start_date: datetime, end_date: datetime) -> Dict:
        """Generate revenue report for time period"""
        query = """
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_analyses,
                SUM(api_cost) as revenue,
                COUNT(DISTINCT user_id) as active_users
            FROM analysis_logs
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date
        """
        
        results = self.db.execute(query, (start_date, end_date)).fetchall()
        
        # Create time series for visualization
        dates = [r['date'] for r in results]
        revenue = [r['revenue'] for r in results]
        users = [r['active_users'] for r in results]
        
        return {
            'total_revenue': sum(revenue),
            'total_analyses': sum(r['total_analyses'] for r in results),
            'unique_users': len(set([r['user_id'] for r in self.db.execute(
                "SELECT DISTINCT user_id FROM analysis_logs WHERE timestamp BETWEEN ? AND ?",
                (start_date, end_date)
            ).fetchall()])),
            'daily_data': {
                'dates': dates,
                'revenue': revenue,
                'active_users': users
            }
        }
    
    def plot_revenue_chart(self, report_data: Dict, output_path: str = 'revenue_chart.png') -> None:
        """Generate revenue visualization"""
        plt.figure(figsize=(12, 6))
        dates = pd.to_datetime(report_data['daily_data']['dates'])
        revenue = report_data['daily_data']['revenue']
        
        sns.set_style("whitegrid")
        plt.plot(dates, revenue, marker='o', linewidth=2, markersize=8)
        plt.fill_between(dates, revenue, alpha=0.3)
        
        plt.title('Daily Revenue', fontsize=16)
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Revenue ($)', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def detect_usage_anomalies(self, user_id: str) -> List[str]:
        """Detect unusual usage patterns that might indicate abuse"""
        alerts = []
        
        # Check for excessive API usage
        month = datetime.utcnow().strftime('%Y-%m')
        monthly_usage = int(self.redis.get(f'user_monthly_usage:{user_id}:{month}') or 0)
        
        if monthly_usage > 1000:  # Threshold for investigation
            alerts.append(f"High usage detected: {monthly_usage} analyses this month")
        
        # Check for repeated failures
        recent_analyses = self.db.execute("""
            SELECT success, analysis_type, COUNT(*) as count
            FROM analysis_logs
            WHERE user_id = ? AND timestamp > datetime('now', '-1 day')
            GROUP BY success, analysis_type
        """, (user_id,)).fetchall()
        
        for result in recent_analyses:
            if not result['success'] and result['count'] > 5:
                alerts.append(f"Multiple failures in {result['analysis_type']}: {result['count']} in 24h")
        
        # Check for unusual binary sizes
        large_binaries = self.db.execute("""
            SELECT binary_size, timestamp
            FROM analysis_logs
            WHERE user_id = ? AND binary_size > 50000000  -- 50MB
            ORDER BY timestamp DESC
            LIMIT 5
        """, (user_id,)).fetchall()
        
        if large_binaries:
            alerts.append(f"Large binary analysis detected: {len(large_binaries)} files over 50MB")
        
        return alerts
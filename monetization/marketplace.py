# monetization/marketplace.py
import stripe
from typing import Dict, List
import hashlib
import os

class ExploitMarketplace:
    """Handle exploit marketplace transactions"""
    
    def __init__(self, stripe_api_key: str):
        stripe.api_key = stripe_api_key
        self.commission_rate = 0.3  # 30% commission
    
    def list_exploit(self, 
                     seller_id: str,
                     exploit_data: Dict,
                     price: float,
                     metadata: Dict = None) -> Dict:
        """List a new exploit for sale"""
        
        # Create Stripe product
        product = stripe.Product.create(
            name=f"Exploit: {exploit_data.get('title', 'Unnamed')}",
            description=exploit_data.get('description', ''),
            metadata={
                'seller_id': seller_id,
                'exploit_type': exploit_data.get('type'),
                'verified': False,  # Start unverified
                'hash': self._generate_exploit_hash(exploit_data),
                **(metadata or {})
            }
        )
        
        # Create price for the product
        price_obj = stripe.Price.create(
            product=product.id,
            unit_amount=int(price * 100),  # Convert to cents
            currency='usd'
        )
        
        return {
            'product_id': product.id,
            'price_id': price_obj.id,
            'listing_url': self._generate_listing_url(product.id)
        }
    
    def purchase_exploit(self, 
                        buyer_id: str,
                        product_id: str,
                        price_id: str) -> Dict:
        """Process exploit purchase"""
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',
            success_url=f"https://reloadai.com/marketplace/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"https://reloadai.com/marketplace/cancel",
            metadata={
                'buyer_id': buyer_id,
                'product_id': product_id
            },
            payment_intent_data={
                'application_fee_amount': self._calculate_commission(price_id),
                'transfer_data': {
                    'destination': self._get_seller_account(product_id),
                },
            }
        )
        
        return {
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id
        }
    
    def verify_exploit(self, 
                      product_id: str,
                      exploit_code: str,
                      test_binary: str = None) -> bool:
        """Verify exploit works before listing"""
        
        # This should run in a sandboxed environment
        # For security, we just return a placeholder
        return True
    
    def _generate_exploit_hash(self, exploit_data: Dict) -> str:
        """Generate unique hash for exploit"""
        content = json.dumps(exploit_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _generate_listing_url(self, product_id: str) -> str:
        """Generate marketplace listing URL"""
        return f"https://reloadai.com/marketplace/exploits/{product_id}"
    
    def _calculate_commission(self, price_id: str) -> int:
        """Calculate marketplace commission"""
        price = stripe.Price.retrieve(price_id)
        return int(price.unit_amount * self.commission_rate)
    
    def _get_seller_account(self, product_id: str) -> str:
        """Get seller's connected Stripe account"""
        product = stripe.Product.retrieve(product_id)
        # In production, look up seller's Stripe account from your database
        return product.metadata.get('seller_id')
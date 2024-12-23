const Seller = require("../models/seller");

const checkRole = (roles) => (req, res, next) => {
    const { sellerId } = req.session; // Assuming you store the sellerId in the session
  
    if (!sellerId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    // Find the seller by sellerId
    Seller.findOne({ sellerId })
      .then((seller) => {
        if (!seller) {
          return res.status(404).json({ error: 'Seller not found' });
        }
  
        // Check if the seller's role is in the allowed roles
        if (roles.includes(seller.role)) {
          req.seller = seller; // Attach the seller object to the request
          next(); // Allow access
        } else {
          res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
        }
      })
      .catch((error) => {
        console.error('Error checking role:', error);
        res.status(500).json({ error: 'Internal server error' });
      });
  };
  
  module.exports = checkRole;
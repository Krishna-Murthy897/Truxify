import express from 'express';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import {
  bidLimiter,
  userLimiter,
  verifyDeliveryLimiter,
  resendOtpLimiter,
  changeDropLimiter,
  createStore,
} from '../middleware/rateLimiter.js';
import { mongoDb, createUserClient, supabaseAdmin } from '../config/db.js';
import { authenticate, requireRole } from '../middleware/auth.js';
import { requirePolicy } from '../middleware/requirePolicy.js';
import { validateBody, validateParams } from '../middleware/validate.js';
import {
  createOrderSchema,
  submitBidSchema,
  submitRatingSchema,
  paramIdSchema,
  verifyDeliverySchema,
  changeDropSchema,
  cancelOrderSchema,
} from '../validation/requestSchemas.js';
import { sendPushNotification } from '../services/notificationService.js';
import { DomainError } from '../services/order/domainError.js';
import { getEscrowBookingId, resolveExpectedDepositAmount, submitEscrowRefund } from '../services/escrow.js';
import { requireIdempotency } from '../middleware/idempotency.js';
import { acquireLockOrFallback } from '../lib/lockFallback.js';
import { acquireLock, releaseLock, LockAcquisitionError } from '../lib/redisLock.js';
import logger from '../middleware/logger.js';
import { auditLog } from '../middleware/auditLog.js';
import {
  orderRepository,
  orderValidationService,
  orderLifecycleService,
  recordDepositTx,
} from '../core/container.js';
import {
  createOrder,
  getActiveOrders,
  getLoadOffers,
  getOrderHistory,
  getOrderDetails,
  verifyDeliveryController,
  getOrderTimeline,
  resendOtp,
  changeDrop,
  cancelOrder,
  verifyDeliveryOtp,
  clearOtpState,
} from '../controllers/orderController.js';

const router = express.Router();
const MAX_GEOFENCE_RADIUS_M = 500;

const injectOtpIdempotencyKey = (req, res, next) => {
  if (req.body && req.body.otp && req.params.id) {
    const otpHash = crypto.createHash('sha256').update(String(req.body.otp).trim()).digest('hex');
    req.headers['x-idempotency-key'] = `${req.params.id}-${otpHash}`;
  }
  next();
};

const milestoneStore = createStore('rl:milestone:');
const milestoneLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'test' ? 1000 : 5,
  keyGenerator: (req) => req.user?.id || 'unknown',
  ...(milestoneStore && typeof milestoneStore.init === 'function' ? { store: milestoneStore } : {}),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many milestone updates. Please slow down.' },
});

// ============================================================================
// 1. CORE ORDER MANAGEMENT
// ============================================================================

// POST /api/orders (Create order)
router.post(
  '/',
  authenticate,
  userLimiter,
  requirePolicy('order:create'),
  validateBody(createOrderSchema),
  createOrder
);

// GET /api/orders/my/active (Customer active orders)
router.get(
  '/my/active',
  authenticate,
  userLimiter,
  requireRole(['customer']),
  getActiveOrders
);

// GET /api/orders/load-offers (Load offers)
router.get(
  '/load-offers',
  authenticate,
  userLimiter,
  getLoadOffers
);

// GET /api/orders/history (Customer order history)
router.get(
  '/history',
  authenticate,
  userLimiter,
  requireRole(['customer']),
  getOrderHistory
);

// GET /api/orders/:id (Order details)
router.get(
  '/:id',
  authenticate,
  userLimiter,
  validateParams(paramIdSchema),
  getOrderDetails
);

// GET /api/orders/:id/timeline (Order timeline)
router.get(
  '/:id/timeline',
  authenticate,
  userLimiter,
  validateParams(paramIdSchema),
  getOrderTimeline
);

// ============================================================================
// 2. BIDS & MARKETPLACE ROUTING
// ============================================================================

// POST /api/orders/:id/bids (Submit bid - Driver)
router.post(
  '/:id/bids',
  authenticate,
  userLimiter,
  bidLimiter,
  requireRole(['driver']),
  requirePolicy('bid:submit'),
  requireIdempotency(3600),
  validateParams(paramIdSchema),
  validateBody(submitBidSchema),
  async (req, res) => {
    try {
      const orderId = req.params.id;
      const { amount } = req.body;
      const driverId = req.user.id;

      const order = await orderValidationService.findOrderByIdOrDisplayId(orderId, 'id, status');
      orderValidationService.assertOrderFound(order);

      const bid = await orderLifecycleService.submitBid({
        orderId: order.id,
        driverId,
        amount,
      });

      return res.status(201).json({
        message: 'Bid submitted successfully.',
        bid,
      });
    } catch (err) {
      if (err instanceof DomainError) {
        return res.status(err.status).json(err.payload);
      }
      logger.error('Submit bid exception:', err.message);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// GET /api/orders/:id/bids (View bids for order - Customer)
router.get(
  '/:id/bids',
  authenticate,
  userLimiter,
  requireRole(['customer']),
  validateParams(paramIdSchema),
  async (req, res) => {
    try {
      const orderId = req.params.id;
      const customerId = req.user.id;

      const order = await orderValidationService.findOrderByIdOrDisplayId(orderId, 'id, customer_id');
      orderValidationService.assertOrderFound(order);
      orderValidationService.assertCustomerOwnership(order, customerId);

      const bids = await orderLifecycleService.getBidsForOrder(order.id);
      return res.json({ bids: bids || [] });
    } catch (err) {
      if (err instanceof DomainError) {
        return res.status(err.status).json(err.payload);
      }
      logger.error('View bids exception:', err.message);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// POST /api/orders/:id/bids/:bidId/accept (Accept a bid - Customer)
router.post(
  '/:id/bids/:bidId/accept',
  authenticate,
  userLimiter,
  requireRole(['customer']),
  requirePolicy('bid:accept'),
  requireIdempotency(3600),
  validateParams(
    z.object({
      id: z.string().uuid('Invalid order ID format'),
      bidId: z.string().uuid('Invalid bid ID format'),
    })
  ),
  async (req, res) => {
    const orderId = req.params.id;
    const bidId = req.params.bidId;
    const customerId = req.user.id;

    const lockKey = `bid_accept_lock:${orderId}`;
    const lock = await acquireLockOrFallback(lockKey, 30000);
    if (!lock.ok) {
      return res.status(409).json({ error: 'Another bid acceptance is in progress for this order. Please try again.' });
    }

    try {
      const order = await orderValidationService.findOrderByIdOrDisplayId(
        orderId,
        'id, customer_id, status, order_display_id'
      );
      orderValidationService.assertOrderFound(order);
      orderValidationService.assertCustomerOwnership(order, customerId);

      const result = await orderLifecycleService.acceptBid({
        orderId: order.id,
        bidId,
        customerId,
      });

      sendPushNotification(
        result.driver_id,
        'Bid Accepted!',
        `Your bid for order ${order.order_display_id} has been accepted. Please fund escrow to proceed.`,
        'order_update',
        { orderId: order.id, orderDisplayId: order.order_display_id }
      ).catch((err) => logger.error(`[FCM] Failed to notify driver of bid acceptance: ${err?.message}`));

      return res.json({
        message: 'Bid accepted successfully. Please proceed with escrow deposit.',
        order: result,
      });
    } catch (err) {
      if (err instanceof DomainError) {
        return res.status(err.status).json(err.payload);
      }
      logger.error('Accept bid exception:', err.message);
      return res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (lock && typeof lock.release === 'function') {
        await lock.release().catch(() => {});
      }
    }
  }
);

// ============================================================================
// 3. ESCROW DEPOSIT CONFIRMATION
// ============================================================================

// POST /api/orders/:id/confirm-deposit
router.post(
  '/:id/confirm-deposit',
  authenticate,
  userLimiter,
  requireRole(['customer']),
  validateParams(paramIdSchema),
  async (req, res) => {
    const orderId = req.params.id;
    const { txHash } = req.body;

    const lockKey = `escrow_lock:${orderId}`;
    let lockValue = null;

    try {
      lockValue = await acquireLock(lockKey, 120000);
      if (!lockValue) {
        return res.status(409).json({ error: 'Another deposit confirmation is in progress for this order. Please try again.' });
      }

      const order = await orderValidationService.findOrderByIdOrDisplayId(
        orderId,
        'id, status, order_display_id, customer_id, escrow_booking_id, escrow_status, escrow_amount_wei, escrow_driver_wallet, pending_bid_acceptance, total_amount, version'
      );
      orderValidationService.assertOrderFound(order);
      orderValidationService.assertCustomerOwnership(order, req.user.id);
      orderValidationService.assertEscrowState(order, ['funding'], 'Order is not in funding state');

      if (order.status === 'cancelled') {
        return res.status(409).json({ error: 'Order is already cancelled. Cannot confirm deposit.' });
      }

      const { data: customerProfile } = await orderRepository.findCustomerWallet(req.user.id);
      const customerWallet = customerProfile?.polygon_wallet_address ?? null;
      const bookingId = order.escrow_booking_id || (order.order_display_id ? getEscrowBookingId(order.order_display_id) : orderId);

      const finalizeAcceptance = async () => {
        const pending = order.pending_bid_acceptance;
        if (!pending) return;

        const { error: acceptErr } = await orderRepository.executeRpc('accept_bid_tx', {
          p_bid_id: pending.bid_id,
          p_order_id: orderId,
          p_load_id: pending.load_id,
          p_driver_id: pending.driver_id,
          p_truck_id: pending.truck_id,
          p_driver_name: pending.driver_name,
          p_driver_rating: pending.driver_rating,
          p_truck_number: pending.truck_number,
          p_bid_amount: pending.bid_amount,
          p_order_display_id: pending.order_display_id,
          p_expected_version: pending.version,
          p_escrow_booking_id: bookingId,
        }, req.token ? createUserClient(req.token) ?? supabaseAdmin : supabaseAdmin);

        if (acceptErr) {
          logger.error('[confirm-deposit] accept_bid_tx failed:', acceptErr.message);

          let refundResult;
          try {
            refundResult = await submitEscrowRefund(order.order_display_id);
          } catch (refundErr) {
            logger.error('[confirm-deposit] Escrow refund also failed:', refundErr.message);
            refundResult = { error: refundErr.message };
          }

          let refundConfirmed = !!(refundResult && !refundResult.error && refundResult.txHash);
          if (refundConfirmed && typeof refundResult.waitForConfirmation === 'function') {
            try {
              await refundResult.waitForConfirmation();
            } catch (confirmErr) {
              logger.error('[confirm-deposit] Escrow refund confirmation failed:', confirmErr.message);
              refundResult = { error: confirmErr.message, txHash: refundResult.txHash };
              refundConfirmed = false;
            }
          } else if (refundConfirmed && typeof refundResult.waitForConfirmation !== 'function') {
            refundConfirmed = false;
            refundResult = {
              error: refundResult.error || 'escrow refund confirmation is unavailable',
              txHash: refundResult.txHash,
            };
          }

          if (!refundConfirmed) {
            const refundError = refundResult?.error || 'escrow refund was not submitted';
            await orderRepository.updateOrder(orderId, {
              escrow_status: 'funding',
              escrow_funding_error: `escrow refund pending: ${refundError}`,
            }).catch((stateErr) => {
              logger.error('[confirm-deposit] Failed to mark escrow refund pending:', stateErr.message);
            });

            throw new DomainError(503, {
              error: 'Deposit confirmed but the driver assignment could not be finalized. The escrow refund is pending and will be completed automatically. Please try again shortly.',
              details: `${acceptErr.message}; escrow refund: ${refundError}`,
            });
          }

          await orderRepository.updateOrder(orderId, {
            pending_bid_acceptance: null,
          }).catch((clearErr) => {
            logger.error('[confirm-deposit] Failed to clear pending_bid_acceptance:', clearErr.message);
          });

          await orderRepository.revertEscrowStatus(orderId).catch((revertErr) => {
            logger.error('[confirm-deposit] Failed to revert escrow status:', revertErr.message);
          });

          throw new DomainError(409, {
            error: 'Deposit confirmed but the driver assignment could not be finalized. The escrow deposit has been refunded. Please try again.',
            details: acceptErr.message,
          });
        }

        sendPushNotification(
          pending.driver_id,
          'Bid Accepted!',
          `Your bid for order ${pending.order_display_id} has been accepted. You are now assigned to this load.`,
          'order_update',
          { orderId, orderDisplayId: pending.order_display_id }
        ).catch((err) => logger.error(`[FCM] Failed to notify driver of bid acceptance: ${err?.message}`));
      };

      const resolvedAmount = resolveExpectedDepositAmount(order);
      if (resolvedAmount.error) {
        return res.status(422).json({ error: resolvedAmount.error, code: resolvedAmount.code });
      }

      const result = await recordDepositTx(
        bookingId,
        txHash,
        customerWallet,
        order.escrow_driver_wallet ?? null,
        resolvedAmount.expectedAmountWei
      );

      if (result.error) {
        return res.status(422).json({ error: result.error, code: result.code });
      }

      const { data: updatedData, error: updateErr } = await orderRepository.updateOrderWithFilter(
        orderId,
        {
          escrow_status: 'funded',
          escrow_funding_error: null,
          version: (order.version || 0) + 1,
          updated_at: new Date().toISOString(),
        },
        [
          { op: 'eq', column: 'escrow_status', value: 'funding' },
          { op: 'eq', column: 'version', value: order.version },
        ],
        'id'
      );

      if (result.alreadyFunded) {
        if (!updateErr && updatedData) {
          await finalizeAcceptance();
          return res.json({ message: 'Escrow deposit confirmed (recovered).', txHash: result.txHash });
        }
        return res.status(202).json({ message: 'Escrow deposit confirmed on-chain. Database sync pending.', txHash: result.txHash });
      }

      if (updateErr) {
        logger.error('[confirm-deposit] DB update failed:', updateErr.message);
        return res.status(500).json({ error: 'Database update failed after deposit confirmation. Please contact support.' });
      }

      await finalizeAcceptance();
      return res.json({ message: 'Escrow deposit confirmed and driver assigned successfully.', txHash: result.txHash });
    } catch (err) {
      if (err instanceof LockAcquisitionError) {
        logger.error('[confirm-deposit] Redis unavailable — refusing deposit confirmation:', err.message);
        return res.status(503).json({ error: 'Payment service temporarily unavailable. Please retry in a moment.' });
      }
      if (err instanceof DomainError) {
        return res.status(err.status).json(err.payload);
      }
      logger.error('[confirm-deposit] Exception:', err.message);
      return res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (lockValue) {
        await releaseLock(lockKey, lockValue).catch((releaseErr) => {
          logger.error('[confirm-deposit] Failed to release order lock:', releaseErr.message);
        });
      }
    }
  }
);

// ============================================================================
// 4. DELIVERY VERIFICATION & OTP (LOCKOUT FIXED)
// ============================================================================

// POST /api/orders/:id/verify-delivery
router.post(
  '/:id/verify-delivery',
  authenticate,
  userLimiter,
  requirePolicy('delivery:verify'),
  auditLog({ action: 'delivery:verify', resourceType: 'delivery_verification' }),
  verifyDeliveryLimiter,
  injectOtpIdempotencyKey,
  requireIdempotency(86400),
  validateParams(paramIdSchema),
  validateBody(verifyDeliverySchema),
  async (req, res) => {
    const orderId = req.params.id;
    try {
      // Step 1: Query and validate order status before verifying OTP
      const order = await orderValidationService.findOrderByIdOrDisplayId(
        orderId,
        'id, status, driver_id, customer_id'
      );
      orderValidationService.assertOrderFound(order);
      orderValidationService.assertDriverAssignment(order, req.user.id);

      // Step 2: Verify Delivery OTP (Brute-force lockout state maintained on failure)
      await verifyDeliveryOtp(orderId, req.body.otp);

      // Step 3: Clear lockout state ONLY after verification succeeds
      await clearOtpState(orderId);

      const result = await orderLifecycleService.verifyDeliveryFn(
        orderId,
        req.user.id,
        req.body.otp,
        req.token ? createUserClient(req.token) : undefined
      );

      return res.status(200).json({
        success: true,
        message: 'Delivery verified successfully.',
        data: result,
      });
    } catch (err) {
      if (err instanceof DomainError) {
        return res.status(err.status).json(err.payload);
      }
      logger.error('[verify-delivery] Exception:', err.message);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// POST /api/orders/:id/confirm-otp (Driver OTP Confirm Alias)
router.post(
  '/:id/confirm-otp',
  authenticate,
  userLimiter,
  requireRole(['driver']),
  verifyDeliveryLimiter,
  injectOtpIdempotencyKey,
  requireIdempotency(86400),
  validateParams(paramIdSchema),
  validateBody(verifyDeliverySchema),
  verifyDeliveryController
);

// POST /api/orders/:id/resend-otp (Driver Resend OTP)
router.post(
  '/:id/resend-otp',
  authenticate,
  userLimiter,
  resendOtpLimiter,
  requireRole(['driver']),
  validateParams(paramIdSchema),
  resendOtp
);

// ============================================================================
// 5. GEOFENCE DELIVERY CONFIRMATION
// ============================================================================

// POST /api/orders/:id/geofence-confirm
router.post(
